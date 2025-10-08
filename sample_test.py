# test_api.py
"""
Comprehensive pytest test file for API testing
This file will be converted to OpenAPI specification
"""

import requests
import pytest

# Base configuration
BASE_URL = "https://api.example.com"
API_VERSION = "v1"

# Test fixtures
@pytest.fixture
def auth_headers():
    """Authentication headers for API requests"""
    return {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive"
    }


# ============================================================================
# USER MANAGEMENT TESTS
# ============================================================================

def test_create_user_with_comprehensive_data(auth_headers):
    """Test creating a new user with comprehensive validation"""
    
    user_data = {
        "firstName": "John",
        "lastName": "Doe",
        "email": "john.doe@company.com",
        "age": 30,
        "active": True,
        "role": "admin",
        "permissions": ["read", "write", "delete"],
        "metadata": {
            "department": "Engineering",
            "team": "Backend",
            "location": "New York"
        }
    }
    
    response = requests.post(
        f"{BASE_URL}/api/{API_VERSION}/users",
        json=user_data,
        headers=auth_headers
    )
    
    # Status code assertion
    assert response.status_code == 201
    
    # Parse response
    result = response.json()
    
    # Basic field assertions
    assert result["firstName"] == "John"
    assert result["lastName"] == "Doe"
    assert result["email"] == "john.doe@company.com"
    assert result["age"] == 30
    assert result["active"] == True
    assert result["role"] == "admin"
    
    # ID validation
    assert result["id"] > 0
    
    # Array assertions
    assert len(result["permissions"]) == 3
    assert "read" in result["permissions"]
    
    # Nested object assertions
    assert result["metadata"]["department"] == "Engineering"
    assert result["metadata"]["team"] == "Backend"
    
    # String validation
    assert result["email"].endswith("@company.com")
    
    # Timestamp assertions
    assert "createdAt" in result
    assert "updatedAt" in result


def test_get_user_by_id(auth_headers):
    """Test retrieving user by ID with query parameters"""
    
    response = requests.get(
        f"{BASE_URL}/api/{API_VERSION}/users/12345",
        params={
            "include": "permissions,roles",
            "fields": "id,firstName,lastName,email"
        },
        headers=auth_headers
    )
    
    # Status validation
    assert response.status_code == 200
    
    # Response parsing
    user = response.json()
    
    # Field presence assertions
    assert "id" in user
    assert "firstName" in user
    assert "email" in user
    
    # Field value assertions
    assert user["id"] == 12345
    assert user["firstName"] == "John"
    assert user["email"] == "john.doe@company.com"
    
    # Type assertions
    assert isinstance(user["permissions"], list)
    
    # Range assertions
    assert user["age"] >= 18


def test_update_user(auth_headers):
    """Test updating user with partial data"""
    
    update_data = {
        "firstName": "Jane",
        "age": 28
    }
    
    response = requests.patch(
        f"{BASE_URL}/api/{API_VERSION}/users/12345",
        json=update_data,
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    updated_user = response.json()
    assert updated_user["firstName"] == "Jane"
    assert updated_user["age"] == 28


def test_delete_user(auth_headers):
    """Test deleting a user"""
    
    response = requests.delete(
        f"{BASE_URL}/api/{API_VERSION}/users/12345",
        headers=auth_headers
    )
    
    assert response.status_code == 204


def test_list_users_with_pagination(auth_headers):
    """Test listing users with pagination"""
    
    response = requests.get(
        f"{BASE_URL}/api/{API_VERSION}/users",
        params={
            "page": 1,
            "limit": 20,
            "sort": "createdAt",
            "order": "desc"
        },
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    data = response.json()
    
    # Response structure assertions
    assert "data" in data
    assert "meta" in data
    assert "pagination" in data
    
    # Data array assertions
    assert isinstance(data["data"], list)
    assert len(data["data"]) <= 20
    
    # Pagination metadata
    assert data["pagination"]["page"] == 1
    assert data["pagination"]["limit"] == 20


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

def test_user_not_found_error(auth_headers):
    """Test 404 error when user doesn't exist"""
    
    response = requests.get(
        f"{BASE_URL}/api/{API_VERSION}/users/999999",
        headers=auth_headers
    )
    
    assert response.status_code == 404
    
    error = response.json()
    
    # Error structure assertions
    assert "error" in error
    assert "message" in error
    assert "code" in error
    
    # Error content assertions
    assert error["message"] == "User not found"
    assert error["code"] == "USER_NOT_FOUND"


def test_validation_error(auth_headers):
    """Test 422 validation error with invalid data"""
    
    invalid_data = {
        "firstName": "",
        "email": "invalid-email",
        "age": -5
    }
    
    response = requests.post(
        f"{BASE_URL}/api/{API_VERSION}/users",
        json=invalid_data,
        headers=auth_headers
    )
    
    assert response.status_code == 422
    
    error = response.json()
    assert error["message"] == "Validation failed"
    assert error["code"] == "VALIDATION_ERROR"


def test_unauthorized_error():
    """Test 401 error when no authentication provided"""
    
    response = requests.get(
        f"{BASE_URL}/api/{API_VERSION}/users/12345"
    )
    
    assert response.status_code == 401
    error = response.json()
    assert error["message"] == "Authentication required"


# ============================================================================
# AUTHENTICATION TESTS
# ============================================================================

def test_login_with_credentials():
    """Test user login and token generation"""
    
    credentials = {
        "username": "john.doe@company.com",
        "password": "SecurePassword123!",
        "rememberMe": True
    }
    
    response = requests.post(
        f"{BASE_URL}/api/{API_VERSION}/auth/login",
        json=credentials,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "TestClient/1.0"
        }
    )
    
    assert response.status_code == 200
    
    result = response.json()
    
    # Token assertions
    assert "accessToken" in result
    assert "refreshToken" in result
    assert "tokenType" in result
    
    assert result["tokenType"] == "Bearer"
    assert len(result["accessToken"]) > 50


def test_refresh_token():
    """Test refreshing access token"""
    
    refresh_data = {
        "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.refresh"
    }
    
    response = requests.post(
        f"{BASE_URL}/api/{API_VERSION}/auth/refresh",
        json=refresh_data,
        headers={"Content-Type": "application/json"}
    )
    
    assert response.status_code == 200
    result = response.json()
    assert "accessToken" in result


# ============================================================================
# SEARCH TESTS
# ============================================================================

def test_search_users(auth_headers):
    """Test searching users with filters"""
    
    response = requests.get(
        f"{BASE_URL}/api/{API_VERSION}/users/search",
        params={
            "q": "john",
            "age_min": 25,
            "department": "Engineering",
            "active": "true"
        },
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    data = response.json()
    assert "results" in data
    assert "total" in data
    assert isinstance(data["results"], list)


# ============================================================================
# BATCH OPERATIONS
# ============================================================================

def test_batch_create_users(auth_headers):
    """Test creating multiple users in batch"""
    
    batch_data = {
        "users": [
            {"firstName": "User1", "email": "user1@example.com", "age": 25},
            {"firstName": "User2", "email": "user2@example.com", "age": 30}
        ]
    }
    
    response = requests.post(
        f"{BASE_URL}/api/{API_VERSION}/users/batch",
        json=batch_data,
        headers=auth_headers
    )
    
    assert response.status_code == 201
    
    result = response.json()
    assert "created" in result
    assert len(result["created"]) >= 1


# ============================================================================
# ANALYTICS
# ============================================================================

def test_get_user_analytics(auth_headers):
    """Test retrieving user analytics"""
    
    response = requests.get(
        f"{BASE_URL}/api/{API_VERSION}/analytics/users",
        params={
            "startDate": "2025-01-01",
            "endDate": "2025-12-31",
            "groupBy": "month"
        },
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    data = response.json()
    assert "metrics" in data
    assert "summary" in data


# ============================================================================
# WEBHOOKS
# ============================================================================

def test_register_webhook(auth_headers):
    """Test registering a webhook endpoint"""
    
    webhook_data = {
        "url": "https://myapp.example.com/webhook",
        "events": ["user.created", "user.updated"],
        "active": True
    }
    
    response = requests.post(
        f"{BASE_URL}/api/{API_VERSION}/webhooks",
        json=webhook_data,
        headers=auth_headers
    )
    
    assert response.status_code == 201
    
    result = response.json()
    assert "webhookId" in result
    assert result["url"] == "https://myapp.example.com/webhook"


# ============================================================================
# HEALTH CHECK
# ============================================================================

def test_health_check():
    """Test API health check endpoint"""
    
    response = requests.get(f"{BASE_URL}/api/{API_VERSION}/health")
    
    assert response.status_code == 200
    
    health = response.json()
    assert "status" in health
    assert health["status"] == "healthy"