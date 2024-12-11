// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::cmp::min;
use std::num::Wrapping;
use std::sync::atomic::{fence, Ordering};

use vm_memory::{bitmap::Bitmap, Address, ByteValued, GuestAddress, GuestMemory};

pub const VIRTQ_DESC_F_NEXT: u16 = 0x1;
pub const VIRTQ_DESC_F_WRITE: u16 = 0x2;

/// Max size of virtio queues offered by firecracker's virtio devices.
pub const FIRECRACKER_MAX_QUEUE_SIZE: u16 = 256;

// GuestMemoryMmap::read_obj_from_addr() will be used to fetch the descriptor,
// which has an explicit constraint that the entire descriptor doesn't
// cross the page boundary. Otherwise the descriptor may be splitted into
// two mmap regions which causes failure of GuestMemoryMmap::read_obj_from_addr().
//
// The Virtio Spec 1.0 defines the alignment of VirtIO descriptor is 16 bytes,
// which fulfills the explicit constraint of GuestMemoryMmap::read_obj_from_addr().

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum QueueError {
    /// Virtio queue number of available descriptors {0} is greater than queue size {1}.
    InvalidQueueSize(u16, u16),
    /// Descriptor index out of bounds: {0}.
    DescIndexOutOfBounds(u16),
    /// Failed to write value into the virtio queue used ring: {0}
    MemoryError(#[from] vm_memory::GuestMemoryError),
}

/// A virtio descriptor constraints with C representative.
/// Taken from Virtio spec:
/// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-430008
/// 2.6.5 The Virtqueue Descriptor Table
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct Descriptor {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

// SAFETY: `Descriptor` is a POD and contains no padding.
unsafe impl ByteValued for Descriptor {}

/// A virtio used element in the used ring.
/// Taken from Virtio spec:
/// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-430008
/// 2.6.8 The Virtqueue Used Ring
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct UsedElement {
    pub id: u32,
    pub len: u32,
}

// SAFETY: `UsedElement` is a POD and contains no padding.
unsafe impl ByteValued for UsedElement {}

/// A virtio descriptor chain.
#[derive(Debug, Copy, Clone)]
#[flux_rs::check_overflow]
pub struct DescriptorChain {
    desc_table_ptr: *const Descriptor,

    queue_size: u16,
    ttl: u16, // used to prevent infinite chain cycles

    /// Index into the descriptor table
    pub index: u16,

    /// Guest physical address of device specific data
    pub addr: GuestAddress,

    /// Length of device specific data
    pub len: u32,

    /// Includes next, write, and indirect bits
    pub flags: u16,

    /// Index into the descriptor table of the next descriptor if flags has
    /// the next bit set
    pub next: u16,
}

impl DescriptorChain {
    /// Creates a new `DescriptorChain` from the given memory and descriptor table.
    ///
    /// Note that the desc_table and queue_size are assumed to be validated by the caller.
    fn checked_new(desc_table_ptr: *const Descriptor, queue_size: u16, index: u16) -> Option<Self> {
        if queue_size <= index {
            return None;
        }

        // SAFETY:
        // index is in 0..queue_size bounds
        let desc = unsafe { desc_table_ptr.add(usize::from(index)).read_volatile() };
        let chain = DescriptorChain {
            desc_table_ptr,
            queue_size,
            ttl: queue_size,
            index,
            addr: GuestAddress(desc.addr),
            len: desc.len,
            flags: desc.flags,
            next: desc.next,
        };

        if chain.is_valid() {
            Some(chain)
        } else {
            None
        }
    }

    fn is_valid(&self) -> bool {
        !self.has_next() || self.next < self.queue_size
    }

    /// Gets if this descriptor chain has another descriptor chain linked after it.
    pub fn has_next(&self) -> bool {
        self.flags & VIRTQ_DESC_F_NEXT != 0 && self.ttl > 1
    }

    /// If the driver designated this as a write only descriptor.
    ///
    /// If this is false, this descriptor is read only.
    /// Write only means the emulated device can write and the driver can read.
    pub fn is_write_only(&self) -> bool {
        self.flags & VIRTQ_DESC_F_WRITE != 0
    }

    /// Gets the next descriptor in this descriptor chain, if there is one.
    ///
    /// Note that this is distinct from the next descriptor chain returned by `AvailIter`, which is
    /// the head of the next _available_ descriptor chain.
    pub fn next_descriptor(&self) -> Option<Self> {
        if self.has_next() {
            DescriptorChain::checked_new(self.desc_table_ptr, self.queue_size, self.next).map(
                |mut c| {
                    c.ttl = self.ttl - 1;
                    c
                },
            )
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct DescriptorIterator(Option<DescriptorChain>);

impl IntoIterator for DescriptorChain {
    type Item = DescriptorChain;
    type IntoIter = DescriptorIterator;

    fn into_iter(self) -> Self::IntoIter {
        DescriptorIterator(Some(self))
    }
}

impl Iterator for DescriptorIterator {
    type Item = DescriptorChain;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.take().map(|desc| {
            self.0 = desc.next_descriptor();
            desc
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// A virtio queue's parameters.
pub struct Queue {
    /// The maximal size in elements offered by the device
    pub max_size: u16,

    /// The queue size in elements the driver selected
    pub size: u16,

    /// Indicates if the queue is finished with configuration
    pub ready: bool,

    /// Guest physical address of the descriptor table
    pub desc_table_address: GuestAddress,

    /// Guest physical address of the available ring
    pub avail_ring_address: GuestAddress,

    /// Guest physical address of the used ring
    pub used_ring_address: GuestAddress,

    /// Host virtual address pointer to the descriptor table
    /// in the guest memory .
    /// Getting access to the underling
    /// data structure should only occur after the
    /// struct is initialized with `new`.
    /// Representation of in memory struct layout.
    /// struct DescriptorTable = [Descriptor; <queue_size>]
    pub desc_table_ptr: *const Descriptor,

    /// Host virtual address pointer to the available ring
    /// in the guest memory .
    /// Getting access to the underling
    /// data structure should only occur after the
    /// struct is initialized with `new`.
    ///
    /// Representation of in memory struct layout.
    /// struct AvailRing {
    ///     flags: u16,
    ///     idx: u16,
    ///     ring: [u16; <queue size>],
    ///     used_event: u16,
    /// }
    ///
    /// Because all types in the AvailRing are u16,
    /// we store pointer as *mut u16 for simplicity.
    pub avail_ring_ptr: *mut u16,

    /// Host virtual address pointer to the used ring
    /// in the guest memory .
    /// Getting access to the underling
    /// data structure should only occur after the
    /// struct is initialized with `new`.
    ///
    /// Representation of in memory struct layout.
    // struct UsedRing {
    //     flags: u16,
    //     idx: u16,
    //     ring: [UsedElement; <queue size>],
    //     avail_event: u16,
    // }
    /// Because types in the UsedRing are different (u16 and u32)
    /// store pointer as *mut u8.
    pub used_ring_ptr: *mut u8,

    pub next_avail: Wrapping<u16>,
    pub next_used: Wrapping<u16>,

    /// VIRTIO_F_RING_EVENT_IDX negotiated (notification suppression enabled)
    pub uses_notif_suppression: bool,
    /// The number of added used buffers since last guest kick
    pub num_added: Wrapping<u16>,
}

/// SAFETY: Queue is Send, because we use volatile memory accesses when
/// working with pointers. These pointers are not copied or store anywhere
/// else. We assume guest will not give different queues  same guest memory
/// addresses.
unsafe impl Send for Queue {}

#[allow(clippy::len_without_is_empty)]
impl Queue {
    /// Constructs an empty virtio queue with the given `max_size`.
    pub fn new(max_size: u16) -> Queue {
        Queue {
            max_size,
            size: 0,
            ready: false,
            desc_table_address: GuestAddress(0),
            avail_ring_address: GuestAddress(0),
            used_ring_address: GuestAddress(0),

            desc_table_ptr: std::ptr::null(),
            avail_ring_ptr: std::ptr::null_mut(),
            used_ring_ptr: std::ptr::null_mut(),

            next_avail: Wrapping(0),
            next_used: Wrapping(0),
            uses_notif_suppression: false,
            num_added: Wrapping(0),
        }
    }

    fn desc_table_size(&self) -> usize {
        std::mem::size_of::<Descriptor>() * usize::from(self.size)
    }

    fn avail_ring_size(&self) -> usize {
        std::mem::size_of::<u16>()
            + std::mem::size_of::<u16>()
            + std::mem::size_of::<u16>() * usize::from(self.size)
            + std::mem::size_of::<u16>()
    }

    fn used_ring_size(&self) -> usize {
        std::mem::size_of::<u16>()
            + std::mem::size_of::<u16>()
            + std::mem::size_of::<UsedElement>() * usize::from(self.size)
            + std::mem::size_of::<u16>()
    }

    fn get_slice_ptr<M: GuestMemory>(
        &self,
        mem: &M,
        addr: GuestAddress,
        len: usize,
    ) -> Result<*mut u8, QueueError> {
        let slice = mem.get_slice(addr, len).map_err(QueueError::MemoryError)?;
        slice.bitmap().mark_dirty(0, len);
        Ok(slice.ptr_guard_mut().as_ptr())
    }

    /// Set up pointers to the queue objects in the guest memory
    /// and mark memory dirty for those objects
    pub fn initialize<M: GuestMemory>(&mut self, mem: &M) -> Result<(), QueueError> {
        self.desc_table_ptr = self
            .get_slice_ptr(mem, self.desc_table_address, self.desc_table_size())?
            .cast();
        self.avail_ring_ptr = self
            .get_slice_ptr(mem, self.avail_ring_address, self.avail_ring_size())?
            .cast();
        self.used_ring_ptr = self
            .get_slice_ptr(mem, self.used_ring_address, self.used_ring_size())?
            .cast();

        if self.actual_size() < self.len() {
            return Err(QueueError::InvalidQueueSize(self.len(), self.actual_size()));
        }

        Ok(())
    }

    /// Mark memory used for queue objects as dirty.
    pub fn mark_memory_dirty<M: GuestMemory>(&self, mem: &M) -> Result<(), QueueError> {
        _ = self.get_slice_ptr(mem, self.desc_table_address, self.desc_table_size())?;
        _ = self.get_slice_ptr(mem, self.avail_ring_address, self.avail_ring_size())?;
        _ = self.get_slice_ptr(mem, self.used_ring_address, self.used_ring_size())?;
        Ok(())
    }

    /// Get AvailRing.idx
    #[inline(always)]
    pub fn avail_ring_idx_get(&self) -> u16 {
        // SAFETY: `idx` is 1 u16 away from the start
        unsafe { self.avail_ring_ptr.add(1).read_volatile() }
    }

    /// Get element from AvailRing.ring at index
    /// # Safety
    /// The `index` parameter should be in 0..queue_size bounds
    #[inline(always)]
    unsafe fn avail_ring_ring_get(&self, index: usize) -> u16 {
        // SAFETY: `ring` is 2 u16 away from the start
        unsafe { self.avail_ring_ptr.add(2).add(index).read_volatile() }
    }

    /// Get AvailRing.used_event
    #[inline(always)]
    pub fn avail_ring_used_event_get(&self) -> u16 {
        // SAFETY: `used_event` is 2 + self.len u16 away from the start
        unsafe {
            self.avail_ring_ptr
                .add(2_usize.unchecked_add(usize::from(self.size)))
                .read_volatile()
        }
    }

    /// Set UsedRing.idx
    #[inline(always)]
    pub fn used_ring_idx_set(&mut self, val: u16) {
        // SAFETY: `idx` is 1 u16 away from the start
        unsafe {
            self.used_ring_ptr
                .add(std::mem::size_of::<u16>())
                .cast::<u16>()
                .write_volatile(val)
        }
    }

    /// Get element from UsedRing.ring at index
    /// # Safety
    /// The `index` parameter should be in 0..queue_size bounds
    #[inline(always)]
    unsafe fn used_ring_ring_set(&mut self, index: usize, val: UsedElement) {
        // SAFETY: `ring` is 2 u16 away from the start
        unsafe {
            self.used_ring_ptr
                .add(std::mem::size_of::<u16>().unchecked_mul(2))
                .cast::<UsedElement>()
                .add(index)
                .write_volatile(val)
        }
    }

    #[inline(always)]
    pub fn used_ring_avail_event_get(&mut self) -> u16 {
        // SAFETY: `avail_event` is 2 * u16 and self.len * UsedElement away from the start
        unsafe {
            self.used_ring_ptr
                .add(
                    std::mem::size_of::<u16>().unchecked_mul(2)
                        + std::mem::size_of::<UsedElement>().unchecked_mul(usize::from(self.size)),
                )
                .cast::<u16>()
                .read_volatile()
        }
    }

    /// Set UsedRing.avail_event
    #[inline(always)]
    pub fn used_ring_avail_event_set(&mut self, val: u16) {
        // SAFETY: `avail_event` is 2 * u16 and self.len * UsedElement away from the start
        unsafe {
            self.used_ring_ptr
                .add(
                    std::mem::size_of::<u16>().unchecked_mul(2)
                        + std::mem::size_of::<UsedElement>().unchecked_mul(usize::from(self.size)),
                )
                .cast::<u16>()
                .write_volatile(val)
        }
    }

    /// Maximum size of the queue.
    pub fn get_max_size(&self) -> u16 {
        self.max_size
    }

    /// Return the actual size of the queue, as the driver may not set up a
    /// queue as big as the device allows.
    pub fn actual_size(&self) -> u16 {
        min(self.size, self.max_size)
    }

    /// Validates the queue's in-memory layout is correct.
    pub fn is_valid<M: GuestMemory>(&self, mem: &M) -> bool {
        let desc_table = self.desc_table_address;
        let desc_table_size = self.desc_table_size();
        let avail_ring = self.avail_ring_address;
        let avail_ring_size = self.avail_ring_size();
        let used_ring = self.used_ring_address;
        let used_ring_size = self.used_ring_size();

        if !self.ready {
            false
        } else if self.size > self.max_size || self.size == 0 || (self.size & (self.size - 1)) != 0
        {
            false
        } else if desc_table.raw_value() & 0xf != 0 {
            false
        } else if avail_ring.raw_value() & 0x1 != 0 {
            false
        } else if used_ring.raw_value() & 0x3 != 0 {
            false
        // range check entire descriptor table to be assigned valid guest physical addresses
        } else if mem.get_slice(desc_table, desc_table_size).is_err() {
            false
        } else if mem.get_slice(avail_ring, avail_ring_size).is_err() {
            false
        } else if mem.get_slice(used_ring, used_ring_size).is_err() {
            false
        } else {
            true
        }
    }

    /// Returns the number of yet-to-be-popped descriptor chains in the avail ring.
    pub fn len(&self) -> u16 {
        (Wrapping(self.avail_ring_idx_get()) - self.next_avail).0
    }

    /// Checks if the driver has made any descriptor chains available in the avail ring.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Pop the first available descriptor chain from the avail ring.
    pub fn pop(&mut self) -> Option<DescriptorChain> {
        let len = self.len();
        // The number of descriptor chain heads to process should always
        // be smaller or equal to the queue size, as the driver should
        // never ask the VMM to process a available ring entry more than
        // once. Checking and reporting such incorrect driver behavior
        // can prevent potential hanging and Denial-of-Service from
        // happening on the VMM side.
        if len > self.actual_size() {
            // We are choosing to interrupt execution since this could be a potential malicious
            // driver scenario. This way we also eliminate the risk of repeatedly
            // logging and potentially clogging the microVM through the log system.
            panic!(
                "The number of available virtio descriptors {len} is greater than queue size: {}!",
                self.actual_size()
            );
        }

        if len == 0 {
            return None;
        }

        self.pop_unchecked()
    }

    /// Try to pop the first available descriptor chain from the avail ring.
    /// If no descriptor is available, enable notifications.
    pub fn pop_or_enable_notification(&mut self) -> Option<DescriptorChain> {
        if !self.uses_notif_suppression {
            return self.pop();
        }

        if self.try_enable_notification() {
            return None;
        }

        self.pop_unchecked()
    }

    /// Pop the first available descriptor chain from the avail ring.
    ///
    /// # Important
    /// This is an internal method that ASSUMES THAT THERE ARE AVAILABLE DESCRIPTORS. Otherwise it
    /// will retrieve a descriptor that contains garbage data (obsolete/empty).
    fn pop_unchecked(&mut self) -> Option<DescriptorChain> {
        // This fence ensures all subsequent reads see the updated driver writes.
        fence(Ordering::Acquire);

        // We'll need to find the first available descriptor, that we haven't yet popped.
        // In a naive notation, that would be:
        // `descriptor_table[avail_ring[next_avail]]`.
        //
        // We use `self.next_avail` to store the position, in `ring`, of the next available
        // descriptor index, with a twist: we always only increment `self.next_avail`, so the
        // actual position will be `self.next_avail % self.actual_size()`.
        let idx = self.next_avail.0 % self.actual_size();
        // SAFETY:
        // index is bound by the queue size
        let desc_index = unsafe { self.avail_ring_ring_get(usize::from(idx)) };

        DescriptorChain::checked_new(self.desc_table_ptr, self.actual_size(), desc_index).map(
            |dc| {
                self.next_avail += Wrapping(1);
                dc
            },
        )
    }

    /// Undo the effects of the last `self.pop()` call.
    /// The caller can use this, if it was unable to consume the last popped descriptor chain.
    pub fn undo_pop(&mut self) {
        self.next_avail -= Wrapping(1);
    }

    /// Write used element into used_ring ring.
    /// - [`ring_index_offset`] is an offset added to
    /// the current [`self.next_used`] to obtain actual index
    /// into used_ring.
    pub fn write_used_element(
        &mut self,
        ring_index_offset: u16,
        desc_index: u16,
        len: u32,
    ) -> Result<(), QueueError> {
        if self.actual_size() <= desc_index {
            return Err(QueueError::DescIndexOutOfBounds(desc_index));
        }

        let next_used = (self.next_used + Wrapping(ring_index_offset)).0 % self.actual_size();
        let used_element = UsedElement {
            id: u32::from(desc_index),
            len,
        };
        // SAFETY:
        // index is bound by the queue size
        unsafe {
            self.used_ring_ring_set(usize::from(next_used), used_element);
        }
        Ok(())
    }

    /// Advance queue and used ring by `n` elements.
    pub fn advance_used_ring(&mut self, n: u16) {
        self.num_added += Wrapping(n);
        self.next_used += Wrapping(n);

        // This fence ensures all descriptor writes are visible before the index update is.
        fence(Ordering::Release);

        self.used_ring_idx_set(self.next_used.0);
    }

    /// Puts an available descriptor head into the used ring for use by the guest.
    pub fn add_used(&mut self, desc_index: u16, len: u32) -> Result<(), QueueError> {
        self.write_used_element(0, desc_index, len)?;
        self.advance_used_ring(1);
        Ok(())
    }

    /// Try to enable notification events from the guest driver. Returns true if notifications were
    /// successfully enabled. Otherwise it means that one or more descriptors can still be consumed
    /// from the available ring and we can't guarantee that there will be a notification. In this
    /// case the caller might want to consume the mentioned descriptors and call this method again.
    pub fn try_enable_notification(&mut self) -> bool {
        // If the device doesn't use notification suppression, we'll continue to get notifications
        // no matter what.
        if !self.uses_notif_suppression {
            return true;
        }

        let len = self.len();
        if len != 0 {
            // The number of descriptor chain heads to process should always
            // be smaller or equal to the queue size.
            if len > self.actual_size() {
                // We are choosing to interrupt execution since this could be a potential malicious
                // driver scenario. This way we also eliminate the risk of
                // repeatedly logging and potentially clogging the microVM through
                // the log system.
                panic!(
                    "The number of available virtio descriptors {len} is greater than queue size: \
                     {}!",
                    self.actual_size()
                );
            }
            return false;
        }

        // Set the next expected avail_idx as avail_event.
        self.used_ring_avail_event_set(self.next_avail.0);

        // Make sure all subsequent reads are performed after we set avail_event.
        fence(Ordering::SeqCst);

        // If the actual avail_idx is different than next_avail one or more descriptors can still
        // be consumed from the available ring.
        self.next_avail.0 == self.avail_ring_idx_get()
    }

    /// Enable notification suppression.
    pub fn enable_notif_suppression(&mut self) {
        self.uses_notif_suppression = true;
    }

    /// Check if we need to kick the guest.
    ///
    /// Please note this method has side effects: once it returns `true`, it considers the
    /// driver will actually be notified, and won't return `true` again until the driver
    /// updates `used_event` and/or the notification conditions hold once more.
    ///
    /// This is similar to the `vring_need_event()` method implemented by the Linux kernel.
    pub fn prepare_kick(&mut self) -> bool {
        // If the device doesn't use notification suppression, always return true
        if !self.uses_notif_suppression {
            return true;
        }

        // We need to expose used array entries before checking the used_event.
        fence(Ordering::SeqCst);

        let new = self.next_used;
        let old = self.next_used - self.num_added;
        let used_event = Wrapping(self.avail_ring_used_event_get());

        self.num_added = Wrapping(0);

        new - used_event - Wrapping(1) < new - old
    }
}
