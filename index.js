const koa = require("koa");
const koaRouter = require("koa-router");
const bodyParser = require("koa-bodyparser");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const qs = require('querystring')
const app = new koa();
const router = new koaRouter();

const port = 8888
const oidcAppId = "应用 ID";
const oidcAppSecret = "应用密钥";
const redirect_uri = `http://localhost:${port}/oidc/handle`

// Authing 控制台 redirect_uri 可以填下面这个。本示例 code 换 token，token 换用户信息都在后端完成。code 由 Authing 以 url query 的形式发到 redirect_uri。
router.get("/oidc/handle", async (ctx, next) => {
  let code = ctx.query.code;
  // code 换 token
  let code2tokenResponse
  try {
    code2tokenResponse = await axios.post(
      // 修改为你的应用域名
      "https://<应用域名>.authing.cn/oidc/token",
      qs.stringify({
        code,
        client_id: oidcAppId,
        client_secret: oidcAppSecret,
        grant_type: "authorization_code",
        redirect_uri
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
  } catch (error) {
    ctx.body = error.response.data
    return
  }
  let { access_token, id_token } = code2tokenResponse.data;
  // token 换用户信息
  let token2UserInfoResponse = await axios.get("https://core.authing.cn/oidc/me?access_token=" + access_token);

  // 解密 id_token
  let decrypted_id_token = jwt.verify(id_token, oidcAppSecret)

  // 这里可以操作用户信息，比如存入数据库
  // ...
  // 把用户重定向到前端登录处理页，携带 id_token，前端需要把这里的 id_token 保存，以后访问受保护资源时要携带

  ctx.body = {
    'code -> access_token response': code2tokenResponse.data,
    'access_token -> userInfo response': token2UserInfoResponse.data,
    'decrypted id_token': decrypted_id_token
  }
});

router.get("/protected/resource", async (ctx, next) => {
  // 用户访问受保护资源需要携带 id_token
  let idToken = ctx.header.authorization || ctx.query.id_token;
  try {
    // 使用 oidc 应用的 clientSecret 进行 token 验证
    // 验证失败，jsonwebtoken 库会抛出错误，比如 token 过期，签名错误
    let decoded = jwt.verify(idToken, oidcAppSecret);
    ctx.body = {
      decoded,
      protected: "This is protected resource."
    }
  } catch (err) {
    // 把用户重定向到 oidc 授权地址，进行登录
    ctx.redirect(
      // 修改为你的应用域名
      `https://<应用域名>.authing.cn/oidc/auth?client_id=${oidcAppId}&redirect_uri=${redirect_uri}&scope=openid%20profile%20offline_access%20phone%20email&response_type=code&state=5435436&nonce=22121&prompt=consent`
    );
  }
});

app.use(bodyParser());
app.use(router.routes());
app.use(router.allowedMethods());
app.listen(port);
console.log(`App listening at http://localhost:${port}`)