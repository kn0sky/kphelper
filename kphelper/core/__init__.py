_EXPORTS = {
    "PROMPTS": ("kphelper.core.constants", "PROMPTS"),
    "REMOTE_DIR": ("kphelper.core.constants", "REMOTE_DIR"),
    "LOCAL_EXP": ("kphelper.core.constants", "LOCAL_EXP"),
    "REMOTE_EXP": ("kphelper.core.constants", "REMOTE_EXP"),
    "find_cpio": ("kphelper.core.discovery", "find_cpio"),
    "find_vmlinux": ("kphelper.core.discovery", "find_vmlinux"),
    "build_exp": ("kphelper.core.build", "build_exp"),
    "upload": ("kphelper.core.upload", "upload"),
    "close_debugger": ("kphelper.core.debug", "close_debugger"),
    "kgdb": ("kphelper.core.debug", "kgdb"),
    "pack_exp": ("kphelper.core.pack", "pack_exp"),
    "symbols_report": ("kphelper.core.symbols", "symbols_report"),
    "guest_ksym_report": ("kphelper.core.ksym", "guest_ksym_report"),
    "create_debug_run_copy": ("kphelper.core.runfile", "create_debug_run_copy"),
    "build_only": ("kphelper.core.workflow", "build_only"),
    "upload_and_cd": ("kphelper.core.workflow", "upload_and_cd"),
    "cd_remote_tmp": ("kphelper.core.session", "cd_remote_tmp"),
    "close_session": ("kphelper.core.session", "close_session"),
    "local_target": ("kphelper.core.session", "local_target"),
    "remote_target": ("kphelper.core.session", "remote_target"),
    "prepare_target": ("kphelper.core.workflow", "prepare_target"),
    "interact": ("kphelper.core.session", "interact"),
}

__all__ = sorted(_EXPORTS)


def __getattr__(name):
    if name not in _EXPORTS:
        raise AttributeError(name)
    module_name, attr_name = _EXPORTS[name]
    module = __import__(module_name, fromlist=[attr_name])
    value = getattr(module, attr_name)
    globals()[name] = value
    return value
