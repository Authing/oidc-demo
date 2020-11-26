# oidc-demo

Authing OIDC RP 端处理方式，基本示例。

帮助不熟悉 OIDC 流程处理方式的开发者熟悉 OIDC 的处理过程。示例中包括 code 换 token，token 换用户信息，受保护资源受访问时判断用户是否有权限，有权限时返回资源，无权限时重定向到 Authing OIDC 登录授权页面。

## 参考文档

1. [创建 OIDC 应用](https://docs.authing.cn/authing/advanced/oidc/create-oidc)
2. [使用 OIDC 授权](https://docs.authing.cn/authing/advanced/oidc/oidc-authorization)
3. [OIDC 常见问题](https://docs.authing.cn/authing/advanced/oidc/oidc-params)

若以上文档无法访问，请将域名改为 `learn.authing.cn`。

## 如何运行

克隆该项目：

```
git clone https://github.com/Authing/oidc-demo/
```

然后运行：

```
$ yarn
$ node index.js
```

## Demo 及原理讲解

### 基础配置

```javascript
const port = 8888;
const oidcAppId = 'OIDC 应用 AppId';
const oidcAppSecret = 'OIDC 应用 AppSecret';
const redirect_uri = `http://localhost:${port}/oidc/handle`;
```

![](http://lcjim-img.oss-cn-beijing.aliyuncs.com/2020-01-04-073932.png)

- oidcAppId 填入 OIDC 应用 AppId
- oidcAppSecret 填入 OIDC 应用 AppSecret
- 将 OIDC 应用的回调 URL 设置为本项目的 `/oidc/handle` 接口

### 使用 Guard 登录获取 Code

点击体验登录访问 Guard 在线地址

![](http://lcjim-img.oss-cn-beijing.aliyuncs.com/2020-01-04-074203.png)

![](http://lcjim-img.oss-cn-beijing.aliyuncs.com/2020-01-04-074319.png)

成功登录之后，将会回调到本项目到 `/oidc/handle`，并且在 Get 请求参数中携带 code。

### 使用 Code 换 Token

```javascript
const qs = require('querystring');

code2tokenResponse = await axios.post(
  'https://<你的应用域名>.authing.cn/oidc/token',
  qs.stringify({
    code,
    client_id: oidcAppId,
    client_secret: oidcAppSecret,
    grant_type: 'authorization_code',
    redirect_uri,
  }),
  {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  }
);
```

有几点需要注意：

- `Content-Type` 为 `application/x-www-form-urlencoded`，非 `application/json`
- Post Body 要转成 `var1=xx&var2=xxx` 的格式。（`qs.stringify()`）

### 使用 Token 换用户信息

```javascript
let token2UserInfoResponse = await axios.get('https://users.authing.cn/oidc/me?access_token=' + access_token);
```

返回的标准 OIDC 用户信息格式如下：

```json
{
  "sub": "5e0db2f0cfe70fe1e5ce0791",
  "birthdate": "",
  "family_name": "",
  "gender": "",
  "given_name": "",
  "locale": "",
  "middle_name": "",
  "name": "",
  "nickname": "廖长江",
  "picture": "https://usercontents.authing.cn/avatar-5e0db2f0cfe70fe1e5ce0791-1577956080139",
  "preferred_username": "",
  "profile": "",
  "updated_at": "",
  "website": "",
  "zoneinfo": ""
}
```

### 携带 id_token 访问 protected resource

```javascript
let idToken = ctx.header.authorization || ctx.query.id_token;
try {
  // 使用 oidc 应用的 clientSecret 进行 token 验证
  // 验证失败，jsonwebtoken 库会抛出错误，比如 token 过期，签名错误
  let decoded = jwt.verify(idToken, oidcAppSecret);
  ctx.body = {
    decoded,
    protected: 'This is protected resource.',
  };
} catch (err) {
  // 把用户重定向到 oidc 授权地址，进行登录
  ctx.redirect(
    `https://<你的应用域名>.authing.cn/oidc/auth?client_id=${oidcAppId}&redirect_uri=${redirect_uri}&scope=openid%20profile%20offline_access%20phone%20email&response_type=code&state=5435436&nonce=22121&prompt=consent`
  );
}
```

- 从 `authorization` 请求头或 `id_token` query 中获取 id_token
- 使用 `oidcAppSecret` 尝试解密
  - 如果成功，说明已经登录，可以返回 protected resource
  - 如果失败，跳转到 `https://<你的应用域名>.authing.cn/oidc/auth?client_id=${oidcAppId}&redirect_uri=${redirect_uri}&scope=openid%20profile%20offline_access%20phone%20email&response_type=code&state=5435436&nonce=22121&prompt=consent`，也即上面提到的登录表单页面。
