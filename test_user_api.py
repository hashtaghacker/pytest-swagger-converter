# test_user_api.py
import requests
import pytest

BASE_URL = "https://api.example.com"

def test_create_user():
    """Test creating a new user"""
    user_data = {
        "name": "John Doe",
        "email": "john@example.com",
        "age": 30,
        "active": True
    }
    
    response = requests.post(
        f"{BASE_URL}/api/v1/users",
        json=user_data,
        headers={"Authorization": "Bearer token123"}
    )
    
    # Status code assertion
    assert response.status_code == 201
    
    # Response body assertions
    result = response.json()
    assert result["name"] == "John Doe"
    assert result["email"] == "john@example.com"
    assert result["id"] > 0
    assert result["active"] == True
    assert "created_at" in result
    assert len(result["permissions"]) >= 1

def test_get_user():
    """Test getting user by ID"""
    response = requests.get(
        f"{BASE_URL}/api/v1/users/123",
        params={"include": "permissions"}
    )
    
    # Multiple status code possibilities
    assert response.status_code == 200
    
    # Response validations
    user = response.json()
    assert isinstance(user["name"], str)
    assert user["age"] >= 18
    assert user["email"].endswith("@example.com")
    assert type(user["permissions"]) == list

def test_get_user_not_found():
    """Test user not found scenario"""
    response = requests.get(f"{BASE_URL}/api/v1/users/999")
    
    assert response.status_code == 404
    error = response.json()
    assert error["message"] == "User not found"
    assert error["code"] == "USER_NOT_FOUND"

def test_update_user():
    """Test updating user information"""
    update_data = {"name": "Jane Doe", "age": 25}
    
    response = requests.put(
        f"{BASE_URL}/api/v1/users/123",
        json=update_data
    )
    
    assert response.status_code == 200
    updated_user = response.json()
    assert updated_user["name"] == "Jane Doe"
    assert updated_user["age"] == 25

def test_delete_user():
    """Test deleting a user"""
    response = requests.delete(f"{BASE_URL}/api/v1/users/123")
    
    assert response.status_code == 204