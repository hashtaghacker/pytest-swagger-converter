#!/usr/bin/env python3
"""
Pytest to Swagger JSON Converter with Enhanced Assertions
Analyzes pytest API test files and generates OpenAPI 3.0 specification with comprehensive assertions
Including JSONPath, header assertions, and human-readable descriptions
"""

import ast
import json
import re
import os
import argparse
from typing import Dict, List, Any, Optional, Set, Union
from pathlib import Path
from urllib.parse import urlparse, urljoin


class PytestToSwaggerConverter:
    """Converts pytest API test files to Swagger/OpenAPI JSON specification with enhanced assertions"""
    
    def __init__(self):
        self.openapi_spec = {
            "openapi": "3.0.3",
            "info": {
                "title": "API Documentation",
                "description": "Generated from pytest tests with assertions",
                "version": "1.0.0"
            },
            "servers": [],
            "paths": {},
            "components": {
                "schemas": {},
                "responses": {},
                "parameters": {},
                "securitySchemes": {}
            }
        }
        self.base_urls = set()
        self.endpoints = {}
        
    def analyze_pytest_file(self, file_path: str) -> None:
        """Analyze a single pytest file for API calls and assertions"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            analyzer = ApiCallAnalyzer()
            
            # Walk through the AST to find function definitions
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    analyzer.current_function = node.name
                    analyzer.current_call_info = None
                    
                    # Process each statement in the function
                    for stmt in node.body:
                        analyzer._process_statement(stmt)
            
            # Process discovered API calls
            for call in analyzer.api_calls:
                self._process_api_call_with_enhanced_assertions(call, file_path)
                
            # Extract base URLs
            for url in analyzer.base_urls:
                self.base_urls.add(url)
                
            print(f"Analyzed {file_path}: Found {len(analyzer.api_calls)} API calls with assertions")
            
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")
            import traceback
            traceback.print_exc()
    
    def _process_api_call_with_enhanced_assertions(self, call_info: Dict[str, Any], file_path: str) -> None:
        """Process API call with enhanced assertions including JSONPath and headers"""
        method = call_info.get('method', '').upper()
        url = call_info.get('url', '')
        
        if not method or not url:
            return
            
        # Extract path from URL and clean up variable placeholders
        parsed_url = urlparse(url)
        path = parsed_url.path or '/'
        
        # Clean up path - remove variable placeholders for cleaner paths
        path = self._clean_path(path)
        
        # Create unique operation ID
        operation_id = f"{method.lower()}_{path.replace('/', '_').replace('{', '').replace('}', '')}"
        if operation_id.endswith('_'):
            operation_id = operation_id[:-1]
        
        # Add server if not exists
        if parsed_url.scheme and parsed_url.netloc:
            server_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            if not any(s['url'] == server_url for s in self.openapi_spec['servers']):
                self.openapi_spec['servers'].append({
                    "url": server_url,
                    "description": "API Server"
                })
        
        # Initialize path in spec
        if path not in self.openapi_spec['paths']:
            self.openapi_spec['paths'][path] = {}
            
        # Initialize method in path with enhanced structure
        if method.lower() not in self.openapi_spec['paths'][path]:
            self.openapi_spec['paths'][path][method.lower()] = {
                "operationId": operation_id,
                "summary": f"{method} {path}",
                "description": f"Generated from pytest test: {call_info.get('test_function', 'unknown')}",
                "servers": [{"url": server_url}] if parsed_url.scheme and parsed_url.netloc else [],
                "parameters": [],
                "responses": {},
                "x-assertion": {  # Enhanced assertion structure
                    "schema": {},
                    "body": [],
                    "path": [],
                    "headers": []
                }
            }
        
        operation = self.openapi_spec['paths'][path][method.lower()]
        
        # Add request body if present
        if call_info.get('data') or call_info.get('json'):
            request_data = call_info.get('json') or call_info.get('data')
            operation['requestBody'] = {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": self._infer_schema_from_data(request_data),
                        "example": request_data
                    }
                }
            }
        
        # Add query parameters
        if call_info.get('params'):
            for param_name, param_value in call_info['params'].items():
                param_schema = self._infer_schema_from_value(param_value)
                operation['parameters'].append({
                    "name": param_name,
                    "in": "query",
                    "required": True,
                    "schema": param_schema,
                    "example": param_value,
                    "default": param_value
                })
        
        # Add path parameters
        path_params = re.findall(r'\{([^}]+)\}', path)
        for param in path_params:
            if not any(p['name'] == param and p['in'] == 'path' for p in operation['parameters']):
                operation['parameters'].append({
                    "name": param,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"}
                })
        
        # Add header parameters
        if call_info.get('headers'):
            headers = call_info['headers']
            # Handle both dict and string representations
            if isinstance(headers, dict):
                for header_name, header_value in headers.items():
                    operation['parameters'].append({
                        "name": header_name,
                        "in": "header",
                        "required": True,
                        "schema": {
                            "type": "string",
                            "default": str(header_value),
                            "example": str(header_value)
                        }
                    })
            elif isinstance(headers, str):
                # Skip string placeholders like <variable:auth_headers>
                pass
        
        # Process assertions with enhanced format
        assertions = call_info.get('assertions', [])
        self._add_enhanced_assertions_to_operation(operation, assertions, call_info)
    
    def _clean_path(self, path: str) -> str:
        """Clean path by removing variable placeholders"""
        # Replace <variable_name> with {variable_name}
        path = re.sub(r'<([^>]+)>', r'{\1}', path)
        return path
    
    def _add_enhanced_assertions_to_operation(self, operation: Dict[str, Any], assertions: List[Dict], call_info: Dict[str, Any]) -> None:
        """Add enhanced assertions in orangehrmlive format"""
        
        # Get status codes
        status_codes = call_info.get('expected_status_codes', [])
        if not status_codes:
            for assertion in assertions:
                if assertion.get('type') == 'status_code' and assertion.get('expected_status'):
                    status_codes.append(assertion.get('expected_status'))
        
        if not status_codes:
            status_codes = [200]
        
        # Build comprehensive schema from assertions
        response_schema = self._build_json_schema_from_assertions(assertions)
        
        # Process each assertion type
        body_assertions = []
        path_assertions = []
        header_assertions = []
        
        for assertion in assertions:
            assertion_type = assertion.get('type')
            
            # Body contains assertions
            if assertion_type == 'contains':
                field = assertion.get('field')
                if field:
                    body_assertions.append({
                        "value": field,
                        "type": "contains",
                        "assertionDescription": f"Check if the response body contains the '{field}' key"
                    })
            
            # JSONPath assertions for field values
            elif assertion_type == 'response_field':
                field = assertion.get('field')
                value = assertion.get('value')
                comparison = assertion.get('comparison', 'equals')
                
                if field and value is not None:
                    json_path = f"$.{field}"
                    comparison_text = self._get_comparison_text(comparison)
                    
                    path_assertions.append({
                        "jsonPath": json_path,
                        "jsonPathValue": str(value),
                        "type": comparison_text,
                        "assertionDescription": f"Check the {field} field {comparison_text} {value}"
                    })
            
            # Header assertions (from headers in call_info)
            elif assertion_type == 'header':
                header_name = assertion.get('name')
                header_value = assertion.get('value')
                if header_name and header_value:
                    header_assertions.append({
                        "assertHeaderKey": header_name,
                        "assertHeaderValue": str(header_value),
                        "assertionDescription": f"Verify {header_name} header is set to {header_value}"
                    })
        
        # Add header assertions from call_info headers
        if call_info.get('headers'):
            headers = call_info['headers']
            # Only process if headers is a dictionary
            if isinstance(headers, dict):
                for header_name, header_value in headers.items():
                    if not any(h['assertHeaderKey'] == header_name for h in header_assertions):
                        header_assertions.append({
                            "assertHeaderKey": header_name,
                            "assertHeaderValue": str(header_value),
                            "assertionDescription": f"Verify {header_name} header is set to {header_value}"
                        })
        
        # Create response objects
        for status_code in status_codes:
            status_str = str(status_code)
            
            response_obj = {
                "description": self._get_status_description(status_code),
                "content": {
                    "application/json": {
                        "schema": {"type": "object"},
                        "example": self._generate_example_from_assertions(assertions),
                        "x-assertion": {
                            "schema": response_schema,
                            "body": body_assertions.copy(),
                            "path": path_assertions.copy(),
                            "headers": header_assertions.copy()
                        }
                    }
                }
            }
            
            operation['responses'][status_str] = response_obj
        
        # Update operation level x-assertion
        operation['x-assertion'] = {
            "schema": response_schema,
            "body": body_assertions,
            "path": path_assertions,
            "headers": header_assertions
        }
    
    def _build_json_schema_from_assertions(self, assertions: List[Dict]) -> Dict[str, Any]:
        """Build complete JSON Schema from assertions"""
        schema = {
            "$schema": "http://json-schema.org/schema#",
            "type": "object",
            "properties": {},
            "required": [],
            "title": "Schema",
            "description": "Schema"
        }
        
        for assertion in assertions:
            assertion_type = assertion.get('type')
            
            if assertion_type == 'response_field':
                field = assertion.get('field')
                value = assertion.get('value')
                
                if field and value is not None:
                    field_schema = self._infer_schema_from_value(value)
                    schema['properties'][field] = field_schema
                    schema['required'].append(field)
            
            elif assertion_type == 'contains':
                field = assertion.get('field')
                if field:
                    schema['properties'][field] = {"type": "string"}
                    schema['required'].append(field)
            
            elif assertion_type == 'response_type':
                field = assertion.get('field')
                expected_type = assertion.get('expected_type')
                if field and expected_type:
                    type_schema = self._map_python_type_to_json_schema(str(expected_type))
                    schema['properties'][field] = type_schema
        
        # Remove duplicates from required
        schema['required'] = list(set(schema['required']))
        
        return schema
    
    def _generate_example_from_assertions(self, assertions: List[Dict]) -> str:
        """Generate example response from assertions"""
        example_obj = {}
        
        for assertion in assertions:
            if assertion.get('type') == 'response_field':
                field = assertion.get('field')
                value = assertion.get('value')
                if field and value is not None:
                    example_obj[field] = value
        
        return json.dumps(example_obj) if example_obj else "{}"
    
    def _get_comparison_text(self, comparison: str) -> str:
        """Convert comparison operator to text"""
        mapping = {
            'equals': 'equal to',
            'not_equals': 'not equal to',
            'greater_than': 'greater than',
            'greater_than_or_equal': 'greater than or equal to',
            'less_than': 'less than',
            'less_than_or_equal': 'less than or equal to',
            'in': 'in',
            'not_in': 'not in',
            'contains': 'contains'
        }
        return mapping.get(comparison, comparison)
    
    def _get_status_description(self, status_code: int) -> str:
        """Get standard HTTP status code descriptions"""
        status_descriptions = {
            200: "OK",
            201: "Created",
            204: "No Content",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            422: "Unprocessable Entity",
            500: "Internal Server Error"
        }
        return status_descriptions.get(status_code, f"HTTP {status_code}")
    
    def _map_python_type_to_json_schema(self, python_type: str) -> Dict[str, Any]:
        """Map Python types to JSON Schema types"""
        # Clean up the type string
        python_type = python_type.replace('<variable:', '').replace('>', '').replace('class ', '').replace("'", "")
        
        type_mapping = {
            'dict': {'type': 'object'},
            'list': {'type': 'array'},
            'str': {'type': 'string'},
            'int': {'type': 'integer'},
            'float': {'type': 'number'},
            'bool': {'type': 'boolean'},
            'NoneType': {'type': 'null'},
            'array': {'type': 'array'},
            'object': {'type': 'object'},
            'string': {'type': 'string'},
            'integer': {'type': 'integer'},
            'number': {'type': 'number'},
            'boolean': {'type': 'boolean'}
        }
        return type_mapping.get(python_type, {'type': 'object'})
    
    def _infer_schema_from_data(self, data: Any) -> Dict[str, Any]:
        """Infer JSON schema from data with more detail"""
        if isinstance(data, dict):
            schema = {"type": "object", "properties": {}}
            required = []
            
            for key, value in data.items():
                schema["properties"][key] = self._infer_schema_from_value(value)
                if value is not None:
                    required.append(key)
            
            if required:
                schema["required"] = required
            return schema
            
        elif isinstance(data, list):
            if data:
                return {
                    "type": "array",
                    "items": self._infer_schema_from_value(data[0])
                }
            else:
                return {"type": "array", "items": {}}
        else:
            return self._infer_schema_from_value(data)
    
    def _infer_schema_from_value(self, value: Any) -> Dict[str, Any]:
        """Infer JSON schema from a single value with validation"""
        if isinstance(value, bool):
            return {"type": "boolean", "example": value}
        elif isinstance(value, int):
            return {"type": "integer", "example": value}
        elif isinstance(value, float):
            return {"type": "number", "example": value}
        elif isinstance(value, str):
            # Skip variable placeholders
            if value.startswith('<variable:') or value.startswith('<'):
                return {"type": "string"}
            schema = {"type": "string", "example": value}
            if len(value) > 0:
                schema["minLength"] = 1
            return schema
        elif isinstance(value, list):
            if value:
                return {
                    "type": "array", 
                    "items": self._infer_schema_from_value(value[0]),
                    "example": value
                }
            return {"type": "array", "items": {"type": "string"}}
        elif isinstance(value, dict):
            return self._infer_schema_from_data(value)
        elif value is None:
            return {"type": "null"}
        else:
            return {"type": "string", "example": str(value)}
    
    def analyze_directory(self, directory: str, pattern: str = "**/test_*.py") -> None:
        """Analyze all pytest files in a directory"""
        path = Path(directory)
        test_files = list(path.glob(pattern))
        
        if not test_files:
            # Try alternative patterns
            patterns = ["**/test_*.py", "**/*_test.py", "**/tests.py", "**/*_tests.py"]
            for pat in patterns:
                test_files.extend(path.glob(pat))
        
        print(f"Found {len(test_files)} test files")
        
        for test_file in test_files:
            self.analyze_pytest_file(str(test_file))
    
    def generate_swagger_json(self, output_file: str = "swagger_with_assertions.json") -> None:
        """Generate and save the Swagger JSON specification with enhanced assertions"""
        # Clean up empty paths
        self.openapi_spec['paths'] = {
            path: methods for path, methods in self.openapi_spec['paths'].items()
            if methods
        }
        
        # Add default server if none found
        if not self.openapi_spec['servers']:
            self.openapi_spec['servers'] = [
                {"url": "http://localhost:8000", "description": "Local development server"}
            ]
        
        # Count assertions
        total_assertions = 0
        for path_data in self.openapi_spec['paths'].values():
            for operation in path_data.values():
                if isinstance(operation, dict) and 'x-assertion' in operation:
                    total_assertions += len(operation['x-assertion'].get('body', []))
                    total_assertions += len(operation['x-assertion'].get('path', []))
                    total_assertions += len(operation['x-assertion'].get('headers', []))
        
        # Update info
        self.openapi_spec['info']['description'] = (
            f"Generated from pytest tests with assertions\n"
            f"Generated from {len(self.openapi_spec['paths'])} endpoints with {total_assertions} test assertions"
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.openapi_spec, f, indent=2, ensure_ascii=False)
        
        print(f"Generated Swagger specification with enhanced assertions: {output_file}")
        print(f"Found {len(self.openapi_spec['paths'])} unique endpoints")
        print(f"Captured {total_assertions} test assertions")


class ApiCallAnalyzer(ast.NodeVisitor):
    """AST visitor to extract API calls and assertions from pytest code"""
    
    def __init__(self):
        self.api_calls = []
        self.base_urls = set()
        self.current_function = None
        self.current_call_info = None
        
    def visit_FunctionDef(self, node):
        """Track current test function"""
        old_function = self.current_function
        self.current_function = node.name
        
        # Process function body to find API calls and their assertions
        for stmt in node.body:
            self._process_statement(stmt)
        
        self.generic_visit(node)
        self.current_function = old_function
    
    def _process_statement(self, stmt):
        """Process a statement to find API calls and subsequent assertions"""
        if isinstance(stmt, ast.Assign):
            # Look for response = requests.method() patterns
            if (len(stmt.targets) == 1 and 
                isinstance(stmt.targets[0], ast.Name) and
                isinstance(stmt.value, ast.Call)):
                
                response_var = stmt.targets[0].id
                call_info = self._extract_api_call_from_assign(stmt.value, response_var)
                if call_info:
                    call_info['test_function'] = self.current_function
                    call_info['response_var'] = response_var
                    self.current_call_info = call_info
                    self.api_calls.append(call_info)
        
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            # Direct function calls like requests.get()
            call_info = self._extract_api_call_from_call(stmt.value)
            if call_info:
                call_info['test_function'] = self.current_function
                self.current_call_info = call_info
                self.api_calls.append(call_info)
        
        elif isinstance(stmt, ast.Assert):
            # Process assert statements
            if self.current_call_info:
                assertion_info = self._extract_assertion_info(stmt)
                if assertion_info:
                    if 'assertions' not in self.current_call_info:
                        self.current_call_info['assertions'] = []
                    self.current_call_info['assertions'].append(assertion_info)
                    
                    # Extract expected status codes
                    if assertion_info.get('type') == 'status_code':
                        status = assertion_info.get('expected_status')
                        if status:
                            if 'expected_status_codes' not in self.current_call_info:
                                self.current_call_info['expected_status_codes'] = []
                            self.current_call_info['expected_status_codes'].append(status)
    
    def _extract_api_call_from_assign(self, call_node, response_var):
        """Extract API call info from assignment like response = requests.get()"""
        return self._extract_api_call_from_call(call_node, response_var)
    
    def _extract_api_call_from_call(self, call_node, response_var=None):
        """Extract API call information from a Call node"""
        # Check for requests.method() pattern
        if (isinstance(call_node.func, ast.Attribute) and
            isinstance(call_node.func.value, ast.Name) and
            call_node.func.value.id == 'requests'):
            
            method = call_node.func.attr.upper()
            return self._extract_request_info(call_node, method, response_var)
        
        # Check for client.method() pattern
        elif (isinstance(call_node.func, ast.Attribute) and
              call_node.func.attr in ['get', 'post', 'put', 'patch', 'delete', 'head', 'options']):
            
            method = call_node.func.attr.upper()
            return self._extract_request_info(call_node, method, response_var)
        
        return None
    
    def visit_Call(self, node):
        """Visit function calls to find API calls"""
        # This is handled by _process_statement now
        self.generic_visit(node)
    
    def visit_Assert(self, node):
        """Visit assert statements to capture test assertions"""
        # This is handled by _process_statement now  
        self.generic_visit(node)
    
    def _extract_request_info(self, node, method, response_var=None):
        """Extract information from a requests call"""
        call_info = {
            'method': method,
            'url': None,
            'data': None,
            'json': None,
            'params': None,
            'headers': None,
            'expected_status_codes': [],
            'response_validations': [],
            'response_var': response_var
        }
        
        # Get URL (first positional argument)
        if node.args:
            url_node = node.args[0]
            call_info['url'] = self._extract_url_from_node(url_node)
            
            if call_info['url']:
                parsed = urlparse(str(call_info['url']))
                if parsed.scheme and parsed.netloc:
                    self.base_urls.add(f"{parsed.scheme}://{parsed.netloc}")
        
        # Get keyword arguments
        for keyword in node.keywords:
            if keyword.arg == 'json':
                extracted = self._extract_literal_value(keyword.value)
                # Only use dict values, skip variable placeholders
                if isinstance(extracted, dict):
                    call_info['json'] = extracted
            elif keyword.arg == 'data':
                extracted = self._extract_literal_value(keyword.value)
                if isinstance(extracted, dict):
                    call_info['data'] = extracted
            elif keyword.arg == 'params':
                extracted = self._extract_literal_value(keyword.value)
                if isinstance(extracted, dict):
                    call_info['params'] = extracted
            elif keyword.arg == 'headers':
                extracted = self._extract_literal_value(keyword.value)
                # Accept both dict and variable references for headers
                if isinstance(extracted, (dict, str)):
                    call_info['headers'] = extracted
        
        return call_info if call_info['url'] else None
    
    def _extract_url_from_node(self, node):
        """Extract URL from various node types"""
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.JoinedStr):
            # Handle f-strings like f"{BASE_URL}/api/users"
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(str(value.value))
                elif isinstance(value, ast.FormattedValue):
                    if isinstance(value.value, ast.Name):
                        parts.append(f"{{{value.value.id}}}")
                    else:
                        parts.append("{dynamic}")
            return ''.join(parts)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            # Handle string concatenation like BASE_URL + "/api/users"
            left = self._extract_url_from_node(node.left)
            right = self._extract_url_from_node(node.right)
            if left and right:
                return str(left) + str(right)
        elif isinstance(node, ast.Name):
            return f"{{{node.id}}}"
        
        try:
            return ast.literal_eval(node)
        except:
            return "{complex_url}"
    
    def _extract_assertion_info(self, node):
        """Extract information from assert statements"""
        if not node.test:
            return None
        
        assertion_info = {
            'type': 'unknown', 
            'raw': ast.unparse(node.test) if hasattr(ast, 'unparse') else self._fallback_unparse(node.test)
        }
        
        # Handle different types of assertions
        if isinstance(node.test, ast.Compare):
            left = node.test.left
            ops = node.test.ops
            comparators = node.test.comparators
            
            if ops and comparators:
                op = ops[0]
                comparator = comparators[0]
                
                # Handle response.status_code assertions
                if (isinstance(left, ast.Attribute) and 
                    left.attr == 'status_code'):
                    
                    assertion_info['type'] = 'status_code'
                    if isinstance(op, ast.Eq) and isinstance(comparator, ast.Constant):
                        assertion_info['expected_status'] = comparator.value
                
                # Handle subscript assertions (both response.json()['field'] and result['field'])
                elif isinstance(left, ast.Subscript):
                    assertion_info['type'] = 'response_field'
                    
                    # Extract field name from subscript
                    field_name = None
                    if isinstance(left.slice, ast.Constant):
                        field_name = left.slice.value
                    elif hasattr(left.slice, 'value') and isinstance(left.slice.value, ast.Constant):
                        # Python < 3.9 compatibility (ast.Index)
                        field_name = left.slice.value.value
                    
                    if field_name:
                        assertion_info['field'] = field_name
                        assertion_info['value'] = self._extract_literal_value(comparator)
                        assertion_info['comparison'] = self._get_comparison_type(op)
                        assertion_info['variable'] = self._extract_literal_value(left.value)
                
                # Handle len() assertions
                elif isinstance(left, ast.Call) and isinstance(left.func, ast.Name) and left.func.id == 'len':
                    assertion_info['type'] = 'response_length'
                    assertion_info['length'] = self._extract_literal_value(comparator)
                    assertion_info['comparison'] = self._get_comparison_type(op)
                    
                    # Try to extract what's being measured
                    if left.args:
                        arg = left.args[0]
                        if isinstance(arg, ast.Subscript) and isinstance(arg.slice, ast.Constant):
                            assertion_info['field'] = arg.slice.value
                
                # Handle isinstance() calls
                elif isinstance(left, ast.Call) and isinstance(left.func, ast.Name) and left.func.id == 'isinstance':
                    assertion_info['type'] = 'response_type'
                    if len(left.args) >= 2:
                        field_expr = left.args[0]
                        type_expr = left.args[1]
                        
                        # Extract field if it's a subscript
                        if isinstance(field_expr, ast.Subscript) and isinstance(field_expr.slice, ast.Constant):
                            assertion_info['field'] = field_expr.slice.value
                        
                        assertion_info['expected_type'] = self._extract_literal_value(type_expr)
                
                # Handle type() assertions
                elif isinstance(left, ast.Call) and isinstance(left.func, ast.Name) and left.func.id == 'type':
                    assertion_info['type'] = 'response_type'
                    assertion_info['expected_type'] = self._extract_literal_value(comparator)
                    
                    # Extract field if the type() call is on a subscript
                    if left.args and isinstance(left.args[0], ast.Subscript):
                        subscript = left.args[0]
                        if isinstance(subscript.slice, ast.Constant):
                            assertion_info['field'] = subscript.slice.value
                
                # Handle string method calls like .endswith()
                elif isinstance(left, ast.Call) and isinstance(left.func, ast.Attribute):
                    method_name = left.func.attr
                    if method_name in ['endswith', 'startswith', 'contains']:
                        assertion_info['type'] = 'string_method'
                        assertion_info['method'] = method_name
                        
                        # Extract the field being tested
                        if isinstance(left.func.value, ast.Subscript) and isinstance(left.func.value.slice, ast.Constant):
                            assertion_info['field'] = left.func.value.slice.value
                        
                        # Extract the expected value
                        if left.args:
                            assertion_info['value'] = self._extract_literal_value(left.args[0])
            
            # Handle 'in' assertions separately
            for i, op in enumerate(node.test.ops):
                if isinstance(op, ast.In):
                    assertion_info['type'] = 'contains'
                    left_val = self._extract_literal_value(node.test.left)
                    right_val = self._extract_literal_value(node.test.comparators[i])
                    
                    # Check if it's a "field in dict" pattern
                    if isinstance(node.test.left, ast.Constant) and isinstance(node.test.comparators[i], ast.Name):
                        assertion_info['field'] = left_val
                        assertion_info['container'] = right_val
                    else:
                        assertion_info['value'] = left_val
                        assertion_info['container'] = right_val
        
        # Handle direct method calls (like result.endswith())
        elif isinstance(node.test, ast.Call):
            if isinstance(node.test.func, ast.Attribute):
                method_name = node.test.func.attr
                assertion_info['type'] = 'method_call'
                assertion_info['method'] = method_name
                
                if node.test.args:
                    assertion_info['value'] = self._extract_literal_value(node.test.args[0])
        
        return assertion_info
    
    def _fallback_unparse(self, node):
        """Fallback method to convert AST to string for older Python versions"""
        try:
            import astor
            return astor.to_source(node).strip()
        except ImportError:
            # Simple fallback
            if isinstance(node, ast.Compare):
                left = getattr(node.left, 'id', str(node.left))
                op = type(node.ops[0]).__name__ if node.ops else 'Unknown'
                right = getattr(node.comparators[0], 'value', str(node.comparators[0])) if node.comparators else 'Unknown'
                return f"{left} {op} {right}"
            return str(type(node).__name__)
    
    def _get_comparison_type(self, op):
        """Map AST comparison operators to string names"""
        if isinstance(op, ast.Eq):
            return 'equals'
        elif isinstance(op, ast.NotEq):
            return 'not_equals'
        elif isinstance(op, ast.Lt):
            return 'less_than'
        elif isinstance(op, ast.LtE):
            return 'less_than_or_equal'
        elif isinstance(op, ast.Gt):
            return 'greater_than'
        elif isinstance(op, ast.GtE):
            return 'greater_than_or_equal'
        elif isinstance(op, ast.In):
            return 'in'
        elif isinstance(op, ast.NotIn):
            return 'not_in'
        elif isinstance(op, ast.Is):
            return 'is'
        elif isinstance(op, ast.IsNot):
            return 'is_not'
        return 'unknown'
    
    def _extract_literal_value(self, node):
        """Extract literal values from AST nodes"""
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Dict):
            result = {}
            for i, key in enumerate(node.keys):
                if i < len(node.values):
                    key_val = self._extract_literal_value(key)
                    val_val = self._extract_literal_value(node.values[i])
                    if key_val is not None:
                        result[key_val] = val_val
            return result
        elif isinstance(node, ast.List):
            return [self._extract_literal_value(item) for item in node.elts]
        elif isinstance(node, ast.Tuple):
            return tuple(self._extract_literal_value(item) for item in node.elts)
        elif isinstance(node, ast.Name):
            return f"<variable:{node.id}>"
        elif isinstance(node, ast.Attribute):
            return f"<attribute:{ast.unparse(node) if hasattr(ast, 'unparse') else 'unknown'}>"
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return f"<call:{node.func.id}>"
            else:
                return f"<call:unknown>"
        else:
            try:
                return ast.literal_eval(node)
            except:
                return f"<unparseable:{type(node).__name__}>"


def main():
    """Main function to run the converter"""
    parser = argparse.ArgumentParser(
        description="Convert pytest API test files to Swagger JSON with enhanced assertions"
    )
    parser.add_argument(
        "input_path", 
        help="Path to pytest file or directory containing test files"
    )
    parser.add_argument(
        "-o", "--output", 
        default="swagger_with_enhanced_assertions.json",
        help="Output file name for the Swagger JSON (default: swagger_with_enhanced_assertions.json)"
    )
    parser.add_argument(
        "-p", "--pattern",
        default="**/test_*.py",
        help="File pattern to match test files (default: **/test_*.py)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output for debugging"
    )
    
    args = parser.parse_args()
    
    converter = PytestToSwaggerConverter()
    
    if os.path.isfile(args.input_path):
        print(f"Analyzing single file: {args.input_path}")
        converter.analyze_pytest_file(args.input_path)
    elif os.path.isdir(args.input_path):
        print(f"Analyzing directory: {args.input_path}")
        converter.analyze_directory(args.input_path, args.pattern)
    else:
        print(f"Error: {args.input_path} is not a valid file or directory")
        return 1
    
    if args.verbose:
        print("\nDebug information:")
        print(f"Base URLs found: {converter.base_urls}")
        print(f"Endpoints found: {list(converter.openapi_spec['paths'].keys())}")
    
    converter.generate_swagger_json(args.output)
    print(f"\nConversion complete! Check {args.output} for the generated Swagger specification with enhanced assertions.")
    return 0


if __name__ == "__main__":
    exit(main())