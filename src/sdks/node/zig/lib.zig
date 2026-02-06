const napi = @import("napi.zig");
const Sandbox = @import("Sandbox.zig");
const Stream = Sandbox.Stream;

export fn napi_register_module_v1(env: napi.c.napi_env, exports: napi.c.napi_value) napi.c.napi_value {
    const funcs = .{
        .{ "createSandbox", napi.ZigExternal(Sandbox).create },
        .{ "sandboxRunCmd", Sandbox.runCmd },
        .{ "streamNext", Stream.next },
    };
    inline for (funcs) |f| {
        napi.registerFunction(env, exports, f[0], f[1]) catch return null;
    }
    return exports;
}
