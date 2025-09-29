# sample_api_test.py - Example pytest file for demonstration
import requests
import pytest

BASE_URL = "https://api.example.com"

def test_create_user():
    """Test creating a new user with validation"""
    user_data = {
        "name": "John Doe",
        "email": "john@example.com", 
        "age": 30,
        "active": True,
        "roles": ["user", "editor"]
    }
    
    response = requests.post(
        f"{BASE_URL}/api/v1/users",
        json=user_data,
        headers={"Authorization": "Bearer token123", "Content-Type": "application/json"}
    )
    
    # Status assertion
    assert response.status_code == 201
    
    # Response field assertions
    result = response.json()
    assert result["name"] == "John Doe"
    assert result["email"] == "john@example.com"
    assert result["id"] > 0
    assert result["active"] == True
    assert result["age"] >= 18
    assert len(result["roles"]) == 2
    assert "created_at" in result

def test_get_user_by_id():
    """Test retrieving a user by ID"""
    response = requests.get(
        f"{BASE_URL}/api/v1/users/123",
        params={"include": "permissions", "format": "detailed"}
    )
    
    assert response.status_code == 200
    
    user = response.json()
    assert isinstance(user["name"], str)
    assert user["age"] >= 18
    assert user["email"].endswith("@example.com")
    assert type(user["permissions"]) == list
    assert len(user["permissions"]) >= 1

def test_user_not_found():
    """Test error handling for non-existent user"""
    response = requests.get(f"{BASE_URL}/api/v1/users/99999")
    
    assert response.status_code == 404
    error = response.json()
    assert error["message"] == "User not found"
    assert error["error_code"] == "USER_NOT_FOUND"
    assert error["status"] == 404

def test_update_user():
    """Test updating user information"""
    update_data = {
        "name": "Jane Smith",
        "age": 25,
        "department": "Engineering"
    }
    
    response = requests.put(
        f"{BASE_URL}/api/v1/users/123",
        json=update_data,
        headers={"Authorization": "Bearer token123"}
    )
    
    assert response.status_code == 200
    updated_user = response.json()
    assert updated_user["name"] == "Jane Smith"
    assert updated_user["age"] == 25
    assert updated_user["department"] == "Engineering"
    assert "updated_at" in updated_user

def test_list_users_with_pagination():
    """Test listing users with pagination parameters"""
    response = requests.get(
        f"{BASE_URL}/api/v1/users",
        params={
            "page": 1,
            "limit": 10,
            "sort": "name",
            "active": True
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data["users"], list)
    assert len(data["users"]) <= 10
    assert data["pagination"]["page"] == 1
    assert data["pagination"]["limit"] == 10
    assert data["pagination"]["total"] >= 0

def test_delete_user():
    """Test deleting a user"""
    response = requests.delete(
        f"{BASE_URL}/api/v1/users/123",
        headers={"Authorization": "Bearer admin_token"}
    )
    
    assert response.status_code == 204

def test_user_authentication_required():
    """Test that authentication is required"""
    response = requests.post(f"{BASE_URL}/api/v1/users", json={"name": "Test"})
    
    assert response.status_code == 401
    error = response.json()
    assert error["message"] == "Authentication required"
    assert error["error_code"] == "UNAUTHORIZED"

def test_user_validation_error():
    """Test validation errors on invalid data"""
    invalid_data = {
        "name": "",  # Empty name should fail
        "email": "invalid-email",  # Invalid email format
        "age": -5  # Invalid age
    }
    
    response = requests.post(
        f"{BASE_URL}/api/v1/users",
        json=invalid_data,
        headers={"Authorization": "Bearer token123"}
    )
    
    assert response.status_code == 422
    error = response.json()
    assert error["message"] == "Validation failed"
    assert isinstance(error["errors"], list)
    assert len(error["errors"]) >= 1