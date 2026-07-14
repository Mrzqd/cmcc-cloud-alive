"""Account login helpers."""

from . import core


def password_login(username, password, state_path=None, save_password=False, account_type=None):
    args = core.argparse.Namespace(
        username=username,
        password=password,
        verification_code="",
        random_code="",
        state=state_path,
        account_type=account_type,
    )
    core.password_login(args)
    if save_password:
        core.merge_state({"password": password, "passwordSavedAt": core.shanghai_now().isoformat()}, args)
    return core.load_state(args)


def login_from_cached_credentials(state_path=None):
    args = core.argparse.Namespace(state=state_path)
    state = core.load_state(args)
    username = state.get("username")
    password = state.get("password")
    if not username or not password:
        raise core.CmccError("cached username/password is required for automatic re-login")
    account_type = core.normalize_account_type(None, state)
    return password_login(
        username,
        password,
        state_path=state_path,
        save_password=True,
        account_type=account_type,
    )
