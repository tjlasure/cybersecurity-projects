from password_manager.utils import load_common_passwords

def test_load_common_passwords():
    common = load_common_passwords()
    assert isinstance(common, list)
    assert "123456" in common  
