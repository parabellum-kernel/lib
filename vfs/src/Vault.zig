const std = @import("std");
const Crypto = @import("Crypto.zig");
const CatalogPort = @import("CatalogPort.zig");
const BlobStorePort = @import("BlobStorePort.zig");
const Packer = @import("Packer.zig");
const Provisioner = @import("Provisioner.zig");
const VfsSession = @import("VfsSession.zig");

/// High-level backend-agnostic VFS Facade (`ARCH-037B`).
/// Manages `vmk`, `catalog_object_id`, `current_etag`, and `RangeCache` across operations.
const Vault = @This();

allocator: std.mem.Allocator,
io: std.Io,
store: BlobStorePort,
catalog: CatalogPort,
session: VfsSession,
vault_id: []u8,
catalog_object_id: []u8,
current_etag: ?[]u8,
vmk: [Crypto.KEY_LEN]u8,

pub const OpenOptions = struct {
    read_cache_max_bytes: usize = 64 * 1024 * 1024,
};

pub const BatchFileInput = struct {
    parent_id: ?[]const u8 = null,
    name: []const u8,
    plaintext: []const u8,
    mime_type: ?[]const u8 = null,
    adaptive_compression: bool = true,
};

pub fn create(
    allocator: std.mem.Allocator,
    io: std.Io,
    store: BlobStorePort,
    catalog: CatalogPort,
    vault_id: []const u8,
    admin_device_id: []const u8,
    admin_device_pk: Crypto.HybridKem.PublicKey,
    nodes: []const Provisioner.NodeConfig,
    opts: OpenOptions,
    now_unix_s: i64,
) !Vault {
    const owned_vid = try allocator.dupe(u8, vault_id);
    errdefer allocator.free(owned_vid);

    var res = try Provisioner.initVault(
        allocator,
        io,
        store,
        catalog,
        vault_id,
        admin_device_id,
        admin_device_pk,
        nodes,
        now_unix_s,
    );
    errdefer res.deinit(allocator);
    allocator.free(res.primary_node_id);

    return .{
        .allocator = allocator,
        .io = io,
        .store = store,
        .catalog = catalog,
        .session = VfsSession.initWithCache(allocator, opts.read_cache_max_bytes),
        .vault_id = owned_vid,
        .catalog_object_id = res.catalog_object_id,
        .current_etag = res.etag,
        .vmk = res.vmk,
    };
}

pub fn open(
    allocator: std.mem.Allocator,
    io: std.Io,
    store: BlobStorePort,
    catalog: CatalogPort,
    vault_id: []const u8,
    catalog_node_id: []const u8,
    catalog_object_id: []const u8,
    device_id: []const u8,
    device_sk: Crypto.HybridKem.SecretKey,
    opts: OpenOptions,
) !Vault {
    const owned_vid = try allocator.dupe(u8, vault_id);
    errdefer allocator.free(owned_vid);

    var res = try Provisioner.unlockVaultFromRemote(
        allocator,
        store,
        catalog,
        vault_id,
        catalog_node_id,
        catalog_object_id,
        device_id,
        device_sk,
    );
    errdefer res.deinit(allocator);

    return .{
        .allocator = allocator,
        .io = io,
        .store = store,
        .catalog = catalog,
        .session = VfsSession.initWithCache(allocator, opts.read_cache_max_bytes),
        .vault_id = owned_vid,
        .catalog_object_id = res.catalog_object_id,
        .current_etag = res.etag,
        .vmk = res.vmk,
    };
}

pub fn deinit(self: *Vault) void {
    self.session.deinit();
    self.allocator.free(self.vault_id);
    self.allocator.free(self.catalog_object_id);
    if (self.current_etag) |e| self.allocator.free(e);
}

pub fn write(
    self: *Vault,
    parent_id: ?[]const u8,
    name: []const u8,
    plaintext: []const u8,
    opts: VfsSession.WriteOptions,
    now_unix_s: i64,
) ![]u8 {
    var ulid_bytes: [16]u8 = undefined;
    self.io.random(&ulid_bytes);
    const inode_id = try std.fmt.allocPrint(self.allocator, "{x}", .{ulid_bytes});
    errdefer self.allocator.free(inode_id);

    const out = try self.session.writeFile(
        self.io,
        self.store,
        self.catalog,
        self.vmk,
        self.vault_id,
        self.catalog_object_id,
        self.current_etag,
        parent_id,
        name,
        inode_id,
        ulid_bytes,
        plaintext,
        opts,
        now_unix_s,
    );

    if (self.current_etag) |e| self.allocator.free(e);
    self.current_etag = out.new_etag;
    return inode_id;
}

pub fn writePacked(
    self: *Vault,
    files: []const BatchFileInput,
    pack_config: Packer.PackConfig,
    now_unix_s: i64,
) ![][]u8 {
    const ids = try self.allocator.alloc([]u8, files.len);
    var built_ids: usize = 0;
    errdefer {
        for (ids[0..built_ids]) |id| self.allocator.free(id);
        self.allocator.free(ids);
    }

    const inputs = try self.allocator.alloc(Packer.SmallFileInput, files.len);
    defer self.allocator.free(inputs);

    for (files, 0..) |f, i| {
        var ulid_bytes: [16]u8 = undefined;
        self.io.random(&ulid_bytes);
        const inode_id = try std.fmt.allocPrint(self.allocator, "{x}", .{ulid_bytes});
        ids[built_ids] = inode_id;
        built_ids += 1;

        inputs[i] = .{
            .parent_id = f.parent_id,
            .name = f.name,
            .inode_id = inode_id,
            .inode_ulid = ulid_bytes,
            .plaintext = f.plaintext,
            .mime_type = f.mime_type,
            .adaptive_compression = f.adaptive_compression,
        };
    }

    const out = try self.session.writePackedFiles(
        self.io,
        self.store,
        self.catalog,
        self.vmk,
        self.vault_id,
        self.catalog_object_id,
        self.current_etag,
        inputs,
        pack_config,
        now_unix_s,
    );

    if (self.current_etag) |e| self.allocator.free(e);
    self.current_etag = out.new_etag;
    return ids;
}

pub fn stat(self: *const Vault, parent_id: ?[]const u8, name: []const u8) ?CatalogPort.Inode {
    return self.catalog.findInodeByName(parent_id, name);
}

pub fn listDir(self: *const Vault, parent_id: ?[]const u8) ![]CatalogPort.Inode {
    return self.catalog.listChildren(self.allocator, parent_id);
}

pub fn mkdir(self: *Vault, parent_id: ?[]const u8, name: []const u8, now_unix_s: i64) ![]u8 {
    var ulid_bytes: [16]u8 = undefined;
    self.io.random(&ulid_bytes);
    const inode_id = try std.fmt.allocPrint(self.allocator, "{x}", .{ulid_bytes});
    errdefer self.allocator.free(inode_id);

    const out = try self.session.mkdir(
        self.io,
        self.store,
        self.catalog,
        self.vmk,
        self.vault_id,
        self.catalog_object_id,
        self.current_etag,
        parent_id,
        name,
        inode_id,
        now_unix_s,
    );
    if (self.current_etag) |e| self.allocator.free(e);
    self.current_etag = out.new_etag;
    return inode_id;
}

pub fn rename(
    self: *Vault,
    inode_id: []const u8,
    new_parent_id: ?[]const u8,
    new_name: []const u8,
    now_unix_s: i64,
) !void {
    const out = try self.session.rename(
        self.io,
        self.store,
        self.catalog,
        self.vmk,
        self.vault_id,
        self.catalog_object_id,
        self.current_etag,
        inode_id,
        new_parent_id,
        new_name,
        now_unix_s,
    );
    if (self.current_etag) |e| self.allocator.free(e);
    self.current_etag = out.new_etag;
}

pub fn delete(self: *Vault, inode_id: []const u8, now_unix_s: i64) !void {
    const out = try self.session.deleteInodeAndMarkGc(
        self.io,
        self.store,
        self.catalog,
        self.vmk,
        self.vault_id,
        self.catalog_object_id,
        self.current_etag,
        inode_id,
        now_unix_s,
    );
    if (self.current_etag) |e| self.allocator.free(e);
    self.current_etag = out.new_etag;
}

pub fn runGc(self: *Vault) !usize {
    const out = try self.session.collectGarbage(
        self.io,
        self.store,
        self.catalog,
        self.vmk,
        self.vault_id,
        self.catalog_object_id,
        self.current_etag,
    );
    if (self.current_etag) |e| self.allocator.free(e);
    self.current_etag = out.new_etag;
    return out.deleted_count;
}

pub fn getQuotas(self: *Vault, now_unix_s: i64) !VfsSession.PoolQuotaSummary {
    return self.session.getQuotas(self.catalog, now_unix_s);
}

pub fn syncQuotasFromRemote(self: *Vault, now_unix_s: i64) !VfsSession.PoolQuotaSummary {
    return self.session.syncQuotasFromRemote(self.store, self.catalog, now_unix_s);
}

pub fn refresh(self: *Vault) !bool {
    const out = try self.session.refreshCatalog(
        self.store,
        self.catalog,
        self.vmk,
        self.vault_id,
        self.catalog_object_id,
        self.current_etag,
    );
    if (self.current_etag) |e| self.allocator.free(e);
    self.current_etag = out.new_etag;
    return out.updated;
}

pub fn readAt(self: *Vault, inode_id: []const u8, offset: u64, out: []u8) !usize {
    if (inode_id.len != 32) return error.InvalidInodeId;
    var ulid_bytes: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ulid_bytes, inode_id);

    return self.session.readFileAt(
        self.store,
        self.catalog,
        self.vmk,
        inode_id,
        ulid_bytes,
        offset,
        out,
    );
}

pub fn addMember(
    self: *Vault,
    slot_id: []const u8,
    label: []const u8,
    role: CatalogPort.SlotRole,
    member_pk: Crypto.HybridKem.PublicKey,
    now_unix_s: i64,
) !void {
    try Provisioner.addMember(
        self.allocator,
        self.io,
        self.catalog,
        self.vault_id,
        self.vmk,
        slot_id,
        label,
        role,
        member_pk,
        now_unix_s,
    );
}

pub fn revokeMember(
    self: *Vault,
    revoked_slot_id: []const u8,
    remaining_slot_ids: []const []const u8,
) !void {
    const new_vmk = try Provisioner.revokeMemberAndRotateVmk(
        self.allocator,
        self.io,
        self.catalog,
        self.vault_id,
        self.vmk,
        revoked_slot_id,
        remaining_slot_ids,
    );
    self.vmk = new_vmk;
}

pub fn signAuthorship(kp: Crypto.Ed25519.KeyPair, payload: []const u8) !Crypto.Ed25519.Signature {
    return Crypto.Ed25519.sign(kp, payload);
}

pub fn verifyAuthorship(pk: Crypto.Ed25519.PublicKey, payload: []const u8, sig: Crypto.Ed25519.Signature) bool {
    return Crypto.Ed25519.verify(pk, payload, sig);
}

pub fn obfuscateName(self: *const Vault, name: []const u8) [32]u8 {
    return Crypto.obfuscateMetadata(self.vmk, self.vault_id, name);
}

