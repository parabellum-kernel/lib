//! Pure, backend-agnostic encrypted Virtual Filesystem (`lib/vfs`, `ARCH-037B`).
//! Applications interact with `Vault`, `CatalogPort`, `BlobStorePort`, and `PoolAllocator.UploadPolicy`.

pub const BlobStorePort = @import("BlobStorePort.zig");
pub const InMemoryBlobStore = @import("InMemoryBlobStore.zig");
pub const CompositeBlobStore = @import("CompositeBlobStore.zig");
pub const CatalogPort = @import("CatalogPort.zig");
pub const InMemoryCatalog = @import("InMemoryCatalog.zig");
pub const Crypto = @import("Crypto.zig");
pub const Compressor = @import("Compressor.zig");
pub const PoolAllocator = @import("PoolAllocator.zig");
pub const StreamConfig = @import("StreamConfig.zig");
pub const Packer = @import("Packer.zig");
pub const PartStream = @import("PartStream.zig");
pub const SyncCoordinator = @import("SyncCoordinator.zig");
pub const Provisioner = @import("Provisioner.zig");
pub const VfsSession = @import("VfsSession.zig");
pub const Vault = @import("Vault.zig");

