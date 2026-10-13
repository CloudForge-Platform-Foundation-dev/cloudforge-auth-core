import pytest
from cloudforge_auth_core.config import AuthConfig

def test_auth_config_accepts_rs256():
    config = AuthConfig(algorithms=("RS256",))
    assert config.algorithms == ("RS256",)

def test_auth_config_rejects_non_rs256():
    with pytest.raises(ValueError):
        AuthConfig(algorithms=("HS256",))
