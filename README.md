# silvaengine_auth

## Configurations

### 1. The following settings should be appended to the configuration data table.

```ini
# 1. Settings of authorizer
region_name=us-east-1
user_pool_id=abc123456789
app_client_id=abc123456789,abc123456789,...
# The `custom_context_hooks` is optional
custom_context_hooks=module_name:class_name:function_name,module_name:class_name:function_name,...

# 2. Settings of silvaengine_auth
app_client_id=abc123456789
app_client_secret=abc123456789
# The `custom_signin_hooks` is optional
custom_signin_hooks=module_name:class_name:function_name,module_name:class_name:function_name,...
```

### 2. Context

2.1. Get data from context

```python
ctx = params.get("context")

seller_id = ctx.get("authorizer").get("seller_id")
s_vendor_id = ctx.get("authorizer").get("s_vendor_id")
team_id = ctx.get("authorizer").get("team_id")
vendor_id = ctx.get("authorizer").get("vendor_id")
cognito_user_sub = ctx.get("authorizer").get("sub")
user_id = ctx.get("authorizer").get("user_id")
is_admin = ctx.get("authorizer").get("is_admin")
roles_of_current_user = ctx.get("additionalContext").get("roles")
```
