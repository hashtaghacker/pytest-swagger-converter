# Pytest to Swagger JSON Converter with Assertions

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A powerful Python tool that converts existing **pytest API test files** into comprehensive **Swagger/OpenAPI 3.0 specifications** with **test assertions transformed into validation rules**. This tool bridges the gap between your actual tested API behavior and formal API documentation.

## 🎯 **Overview**

Unlike typical tools that generate tests FROM API specs, this converter works in reverse - it analyzes your existing pytest test files and generates OpenAPI specifications that reflect the **actual behavior verified by your tests**. Your test assertions become OpenAPI validation rules, ensuring your documentation matches what your tests actually verify.

## 🌟 **Key Features**

- ✅ **Assertion-Driven Validation**: Converts pytest assertions into OpenAPI schema validation rules
- ✅ **Complete API Specification**: Generates full OpenAPI 3.0 specs with endpoints, parameters, and schemas
- ✅ **Smart Schema Inference**: Automatically infers data types and constraints from test data
- ✅ **Test Metadata Preservation**: Stores detailed assertion information in custom `x-test-assertions` extension
- ✅ **Multiple Test Pattern Support**: Handles various pytest naming conventions and structures
- ✅ **Complex URL Parsing**: Supports f-strings, concatenation, and variable references
- ✅ **Living Documentation**: API specs that stay in sync with your actual tests

## 🔧 **Installation**

### Prerequisites
- Python 3.7 or higher
- pytest test files with API calls using `requests` library

### Setup
```bash
# Clone or download the converter
git clone <repository-url>
cd pytest-swagger-converter

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install requests pytest pathlib argparse

# Optional: Install for better AST parsing
pip install astor
```

## 📖 **Usage**

### Basic Usage

```bash
# Convert single test file
python pytest_to_swagger.py test_api.py -o api_spec.json

# Convert test directory
python pytest_to_swagger.py ./tests -o complete_api.json

# Use custom file pattern
python pytest_to_swagger.py ./tests -p "**/test_*_api.py" -o api_docs.json

# Verbose output for debugging
python pytest_to_swagger.py test_file.py -o output.json -v
```

### Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `input_path` | - | Path to pytest file or directory | Required |
| `--output` | `-o` | Output JSON file name | `swagger_with_assertions.json` |
| `--pattern` | `-p` | File pattern for test discovery | `**/test_*.py` |
| `--verbose` | `-v` | Enable verbose debugging output | False |

### File Pattern Examples

```bash
# Standard pytest patterns
python pytest_to_swagger.py ./tests -p "**/test_*.py"
python pytest_to_swagger.py ./tests -p "**/*_test.py"
python pytest_to_swagger.py ./tests -p "**/test_*.py,**/*_test.py"

# Custom patterns
python pytest_to_swagger.py ./api_tests -p "**/integration_*.py"
python pytest_to_swagger.py ./tests -p "**/api/**/*.py"
```

## 📝 **Input Format**

### Supported Test Patterns

The converter analyzes pytest files looking for HTTP API calls and their associated assertions. Here are the supported patterns:

#### 1. **Basic API Calls**
```python
import requests

def test_create_user():
    # Direct URL
    response = requests.post("https://api.example.com/users", json={"name": "John"})
    
    # URL with variables
    BASE_URL = "https://api.example.com"
    response = requests.get(f"{BASE_URL}/users/123")
    
    # URL concatenation
    response = requests.put(BASE_URL + "/users/123", json=data)
```

#### 2. **Request Parameters**
```python
def test_with_parameters():
    response = requests.get(
        "https://api.example.com/users",
        params={"page": 1, "limit": 10},
        headers={"Authorization": "Bearer token123"},
        json={"name": "John", "email": "john@example.com"}
    )
```

#### 3. **Supported HTTP Methods**
- `requests.get()`
- `requests.post()`
- `requests.put()`
- `requests.patch()`
- `requests.delete()`
- `requests.head()`
- `requests.options()`

#### 4. **Custom Client Support**
```python
def test_with_custom_client(api_client):
    # Also supports custom client patterns
    response = api_client.post("/users", json=data)
    response = client.get("/users/123")
```

### Supported Assertion Patterns

The converter transforms various pytest assertion patterns into OpenAPI validation rules:

#### **Status Code Assertions**
```python
assert response.status_code == 201
assert response.status_code == 200
assert response.status_code == 404
```
**→ Generates**: Appropriate HTTP response definitions

#### **Response Field Assertions**
```python
# Direct response parsing
result = response.json()
assert result["name"] == "John Doe"           # → enum: ["John Doe"]
assert result["id"] > 0                       # → minimum: 1
assert result["age"] >= 18                    # → minimum: 18
assert result["score"] <= 100                 # → maximum: 100
assert result["active"] == True               # → enum: [true]
```
**→ Generates**: Field validation rules in response schema

#### **String Method Assertions**
```python
assert result["email"].endswith("@company.com")  # → pattern: .*@company\.com$
assert result["name"].startswith("Mr.")          # → pattern: ^Mr\..*
```
**→ Generates**: String pattern validation

#### **Length and Array Assertions**
```python
assert len(result["items"]) >= 5              # → minItems: 5
assert len(result["tags"]) == 3               # → minItems: 3, maxItems: 3
assert len(result["errors"]) < 10             # → maxItems: 9
```
**→ Generates**: Array length constraints

#### **Type Assertions**
```python
assert isinstance(result["data"], list)       # → type: array
assert isinstance(result["count"], int)       # → type: integer
assert type(result["name"]) == str            # → type: string
```
**→ Generates**: Appropriate JSON schema types

#### **Containment Assertions**
```python
assert "created_at" in result                 # → Field marked as required
assert "error" not in result                  # → Field marked as optional
assert result["status"] in ["active", "inactive"]  # → enum: ["active", "inactive"]
```
**→ Generates**: Required field specifications and enums

### Example Input File

```python
# test_user_api.py
import requests

BASE_URL = "https://api.example.com"

def test_create_user():
    """Test creating a new user with comprehensive validation"""
    user_data = {
        "name": "John Doe",
        "email": "john@company.com",
        "age": 30,
        "active": True,
        "roles": ["user", "editor"]
    }
    
    response = requests.post(
        f"{BASE_URL}/api/v1/users",
        json=user_data,
        headers={
            "Authorization": "Bearer token123",
            "Content-Type": "application/json"
        }
    )
    
    # Status validation
    assert response.status_code == 201
    
    # Response structure validation
    result = response.json()
    assert result["name"] == "John Doe"
    assert result["email"] == "john@company.com"
    assert result["id"] > 0
    assert result["active"] == True
    assert result["age"] >= 18
    assert len(result["roles"]) == 2
    assert "created_at" in result
    assert result["email"].endswith("@company.com")

def test_get_user():
    """Test retrieving user with error handling"""
    response = requests.get(
        f"{BASE_URL}/api/v1/users/123",
        params={"include": "permissions"}
    )
    
    assert response.status_code == 200
    user = response.json()
    assert isinstance(user["permissions"], list)
    assert len(user["permissions"]) >= 1

def test_user_not_found():
    """Test 404 error scenario"""
    response = requests.get(f"{BASE_URL}/api/v1/users/99999")
    
    assert response.status_code == 404
    error = response.json()
    assert error["message"] == "User not found"
    assert error["code"] == "USER_NOT_FOUND"
```

## 📄 **Output Format**

The converter generates a comprehensive OpenAPI 3.0 specification with two main components:

### 1. **Standard OpenAPI Specification**

```json
{
  "openapi": "3.0.3",
  "info": {
    "title": "API Documentation",
    "description": "Generated from pytest tests with assertions",
    "version": "1.0.0"
  },
  "servers": [
    {
      "url": "https://api.example.com",
      "description": "API Server"
    }
  ],
  "paths": {
    "/api/v1/users": {
      "post": {
        "operationId": "post_api_v1_users",
        "summary": "POST /api/v1/users",
        "description": "Generated from pytest test: test_create_user",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "name": {"type": "string", "example": "John Doe"},
                  "email": {"type": "string", "example": "john@company.com"},
                  "age": {"type": "integer", "example": 30},
                  "active": {"type": "boolean", "example": true},
                  "roles": {
                    "type": "array",
                    "items": {"type": "string"},
                    "example": ["user", "editor"]
                  }
                },
                "required": ["name", "email", "age", "active", "roles"]
              }
            }
          }
        },
        "parameters": [
          {
            "name": "Authorization",
            "in": "header",
            "required": false,
            "schema": {"type": "string"},
            "example": "Bearer token123"
          }
        ],
        "responses": {
          "201": {
            "description": "Created - Resource successfully created",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "name": {
                      "type": "string",
                      "enum": ["John Doe"],
                      "example": "John Doe"
                    },
                    "email": {
                      "type": "string",
                      "pattern": ".*@company\\.com$",
                      "enum": ["john@company.com"],
                      "example": "john@company.com"
                    },
                    "id": {
                      "type": "integer",
                      "minimum": 1,
                      "example": 0
                    },
                    "active": {
                      "type": "boolean",
                      "enum": [true],
                      "example": true
                    },
                    "age": {
                      "type": "integer",
                      "minimum": 18,
                      "example": 30
                    },
                    "roles": {
                      "type": "array",
                      "items": {"type": "string"},
                      "minItems": 2,
                      "maxItems": 2
                    },
                    "created_at": {
                      "type": "string"
                    }
                  },
                  "required": ["name", "email", "id", "active", "age", "roles", "created_at"]
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### 2. **Detailed Assertion Metadata** (`x-test-assertions`)

```json
{
  "x-test-assertions": {
    "POST:/api/v1/users": [
      {
        "test_function": "test_create_user",
        "file_path": "./test_user_api.py",
        "assertions": [
          {
            "type": "status_code",
            "expected_status": 201,
            "raw": "response.status_code == 201"
          },
          {
            "type": "response_field",
            "field": "name",
            "value": "John Doe",
            "comparison": "equals",
            "raw": "result['name'] == 'John Doe'"
          },
          {
            "type": "response_field",
            "field": "id",
            "value": 0,
            "comparison": "greater_than",
            "raw": "result['id'] > 0"
          },
          {
            "type": "string_method",
            "field": "email",
            "method": "endswith",
            "value": "@company.com",
            "raw": "result['email'].endswith('@company.com')"
          },
          {
            "type": "response_length",
            "field": "roles",
            "length": 2,
            "comparison": "equals",
            "raw": "len(result['roles']) == 2"
          },
          {
            "type": "contains",
            "field": "created_at",
            "container": "<variable:result>",
            "raw": "'created_at' in result"
          }
        ],
        "expected_status_codes": [201]
      }
    ]
  }
}
```

## 🎨 **Assertion to OpenAPI Mapping**

### Complete Mapping Table

| Pytest Assertion | Assertion Type | OpenAPI Schema Rule | Example |
|------------------|----------------|-------------------|---------|
| `result["field"] == "value"` | `response_field` | `enum: ["value"]` | String exact match |
| `result["id"] > 0` | `response_field` | `minimum: 1` | Positive integer |
| `result["age"] >= 18` | `response_field` | `minimum: 18` | Minimum value |
| `result["score"] <= 100` | `response_field` | `maximum: 100` | Maximum value |
| `result["email"].endswith("@test.com")` | `string_method` | `pattern: ".*@test\\.com$"` | String pattern |
| `len(result["items"]) >= 5` | `response_length` | `minItems: 5` | Array minimum length |
| `len(result["tags"]) == 3` | `response_length` | `minItems: 3, maxItems: 3` | Exact array length |
| `isinstance(result["data"], list)` | `response_type` | `type: "array"` | Type validation |
| `"field" in result` | `contains` | Field in `required` array | Required field |
| `response.status_code == 201` | `status_code` | HTTP 201 response definition | Status code |

### Schema Generation Rules

1. **Enum Values**: Exact equality assertions (`==`) become `enum` constraints
2. **Numeric Ranges**: Comparison assertions (`>`, `>=`, `<`, `<=`) become `minimum`/`maximum` constraints  
3. **String Patterns**: Method calls (`.endswith()`, `.startswith()`) become `pattern` regex constraints
4. **Array Lengths**: `len()` assertions become `minItems`/`maxItems` constraints
5. **Required Fields**: `in` containment assertions mark fields as required
6. **Type Validation**: `isinstance()` and `type()` assertions set JSON schema types

## 🚀 **Use Cases**

### 1. **API Documentation Generation**
```bash
# Generate comprehensive API docs from your test suite
python pytest_to_swagger.py ./tests/api -o docs/api-specification.json

# Use with Swagger UI for interactive documentation
swagger-ui-serve docs/api-specification.json
```

### 2. **Contract Testing**
```bash
# Generate specs that enforce tested behavior
python pytest_to_swagger.py ./integration_tests -o contracts/api-contract.json

# Use generated specs for contract validation
```

### 3. **Mock Server Generation**
```bash
# Create OpenAPI spec from tests
python pytest_to_swagger.py ./tests -o mock-server-spec.json

# Generate mock server from spec
prism mock mock-server-spec.json
```

### 4. **API Client Generation**
```bash
# Generate spec with validation rules
python pytest_to_swagger.py ./tests -o client-spec.json

# Generate typed API clients
openapi-generator generate -i client-spec.json -g python-client -o ./api-client
```

### 5. **CI/CD Integration**
```yaml
# .github/workflows/api-docs.yml
name: Generate API Documentation
on: [push]
jobs:
  generate-docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      - name: Generate API Spec
        run: |
          pip install requests pytest
          python pytest_to_swagger.py ./tests/api -o api-spec.json
      - name: Deploy to Documentation Site
        run: |
          # Upload to your documentation platform
```

## 🔍 **Advanced Features**

### Verbose Output
```bash
python pytest_to_swagger.py test_file.py -o output.json -v
```
Shows:
- Discovered base URLs
- Found endpoints
- Assertion parsing details
- Schema generation process

### Complex URL Handling
The converter handles various URL patterns:
```python
# F-strings
response = requests.get(f"{BASE_URL}/users/{user_id}")

# String concatenation  
response = requests.get(BASE_URL + "/api/v1/users")

# Variable substitution (marked as <variable_name>)
url = get_api_url()
response = requests.get(url)  # → Shows as <variable:url>
```

### Multiple Test Files
```bash
# Process entire test suites with different patterns
python pytest_to_swagger.py ./tests \
  -p "**/test_*_api.py,**/integration_test_*.py,**/*_api_test.py" \
  -o complete-api-spec.json
```

## 🐛 **Troubleshooting**

### Common Issues

#### 1. **No API calls found**
```
Found 0 API calls with assertions
```
**Solutions:**
- Ensure test files use `requests.get()`, `requests.post()`, etc.
- Check file naming matches pattern (default: `test_*.py`)
- Verify imports: `import requests`
- Use `-v` flag for debugging

#### 2. **Unknown assertion types**
```json
{"type": "unknown", "raw": "some_assertion"}
```
**Solutions:**
- Check supported assertion patterns above
- Simplify complex assertion logic
- Use standard comparison operators (`==`, `>`, `<`, etc.)

#### 3. **Missing URL parsing**
```
URL shows as <complex_url>
```
**Solutions:**  
- Use simple string concatenation or f-strings
- Avoid complex URL building logic
- Define URLs as constants when possible

#### 4. **PowerShell execution policy errors**
```
execution of scripts is disabled on this system
```
**Solution:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Debug Mode
```bash
python pytest_to_swagger.py test_file.py -o output.json -v
```
Provides detailed information about:
- AST parsing process
- API call discovery
- Assertion extraction
- Schema generation

## 📊 **Output Statistics**

After conversion, the tool reports:
- **Unique endpoints discovered**: Number of API paths found
- **Test assertions captured**: Total assertions converted to validation rules
- **Base URLs identified**: API server endpoints
- **Response status codes**: HTTP status codes from assertions

Example output:
```
Analyzed test_user_api.py: Found 8 API calls with assertions
Generated Swagger specification with assertions: api_spec.json
Found 4 unique endpoints
Captured 23 test assertions
```

## 🎯 **Benefits**

### For Development Teams
- **Living Documentation**: API docs automatically stay in sync with tests
- **Contract Enforcement**: Generated schemas enforce tested behavior
- **Reduced Maintenance**: No need to manually maintain separate API documentation
- **Quality Assurance**: Documentation reflects actual tested scenarios

### for DevOps/CI-CD
- **Automated Documentation**: Generate API specs in CI/CD pipelines
- **Contract Testing**: Ensure API providers match consumer expectations
- **Mock Generation**: Create realistic mock servers from test data
- **Client Generation**: Generate API clients with proper validation

### For API Consumers
- **Accurate Schemas**: Response validation based on actual test assertions
- **Realistic Examples**: Request/response examples from real test data
- **Behavioral Documentation**: Understand API behavior through test scenarios

## 🔮 **Limitations**

### Current Limitations
- **Static Analysis Only**: Cannot analyze dynamic or computed values
- **Requests Library Focus**: Primarily supports `requests` HTTP calls
- **Python AST Dependent**: Requires valid Python syntax
- **Simple Assertion Logic**: Complex nested assertions may not be fully captured

### Workarounds
- Use simple, direct assertions when possible
- Define variables as constants for better URL parsing
- Break complex assertions into multiple simple ones
- Use standard `requests` patterns

## 📚 **Related Tools**

### Complementary Tools
- **Swagger UI**: Visualize generated specifications
- **Prism**: Create mock servers from OpenAPI specs  
- **OpenAPI Generator**: Generate clients from specifications
- **Postman**: Import OpenAPI specs for API testing

### Integration Examples
```bash
# Generate spec and start mock server
python pytest_to_swagger.py ./tests -o api-spec.json
prism mock api-spec.json

# Generate spec and create documentation site  
python pytest_to_swagger.py ./tests -o api-spec.json
swagger-ui-serve api-spec.json

# Generate spec and create API client
python pytest_to_swagger.py ./tests -o api-spec.json
openapi-generator generate -i api-spec.json -g python-client -o ./client
```

## 🤝 **Contributing**

### Development Setup
```bash
git clone <repository-url>
cd pytest-swagger-converter
python -m venv venv
source venv/bin/activate  # or .\venv\Scripts\Activate.ps1 on Windows
pip install -r requirements.txt
```

### Adding New Assertion Types
1. Update `_extract_assertion_info()` method
2. Add mapping in `_add_assertions_to_operation()`
3. Update documentation and tests
4. Submit pull request

## 📄 **License**

MIT License - see LICENSE file for details.

## 🙋‍♀️ **Support**

### Getting Help
- **Issues**: Report bugs or request features via GitHub issues
- **Discussions**: Ask questions in GitHub discussions  
- **Documentation**: Check this README for comprehensive guidance

### Common Questions
**Q: Can it handle custom HTTP clients?**
A: Limited support - works best with standard `requests` patterns

**Q: Does it support async tests?**  
A: Currently focuses on synchronous `requests` calls

**Q: Can it parse pytest fixtures?**
A: Basic support - works best with direct API calls in test functions

**Q: What Python versions are supported?**
A: Python 3.7+ (ast.unparse available in 3.9+, fallback included)

---

**🚀 Transform your pytest API tests into comprehensive OpenAPI documentation with validation rules that actually reflect your tested behavior!**