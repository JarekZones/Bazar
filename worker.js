const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
};

export default {
  async fetch(request, env) {
    const origin = env.ALLOWED_ORIGIN || "*";

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin),
      });
    }

    try {
      const url = new URL(request.url); 
      }
      
      // Přihlášení administrátora
      if (url.pathname === "/api/auth" && request.method === "POST") {
        return await handleAuth(request, env, origin);
      }

      // Načtení produktů pro administraci
      if (url.pathname === "/api/admin/data" && request.method === "GET") {
        await requireAuth(request, env);
        return await handleAdminData(env, origin);
      }

      // Nahrání obrázku
      if (url.pathname === "/api/image" && request.method === "POST") {
        await requireAuth(request, env);
        return await handleImageUpload(request, env, origin);
      }

      // Uložení produktů
      if (url.pathname === "/api/save" && request.method === "POST") {
        await requireAuth(request, env);
        return await handleSave(request, env, origin);
      }

      return json(
        { error: "Požadovaná stránka nebyla nalezena." },
        404,
        origin
      );

    } catch (error) {
      console.error(error);

      const status =
        error instanceof HttpError
          ? error.status
          : 500;

      return json(
        {
          error:
            error instanceof Error
              ? error.message
              : "Interní chyba serveru."
        },
        status,
        origin
      );
    }
  }
};


// ============================================================
// CORS
// ============================================================

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization",
    "Access-Control-Allow-Methods":
      "GET, POST, OPTIONS",
    "Vary": "Origin",
  };
}


// ============================================================
// JSON RESPONSE
// ============================================================

function json(data, status = 200, origin = "*") {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        ...JSON_HEADERS,
        ...corsHeaders(origin),
      },
    }
  );
}


// ============================================================
// LOGIN
// ============================================================

async function handleAuth(request, env, origin) {

  const body =
    await request.json().catch(() => ({}));

  const password =
    String(body.password || "");

  if (
    !env.ADMIN_PASSWORD ||
    password !== env.ADMIN_PASSWORD
  ) {
    return json(
      {
        error: "Neplatné heslo."
      },
      401,
      origin
    );
  }

  const token =
    await createToken(env.SESSION_SECRET);

  return json(
    {
      token: token,
      expiresIn: 8 * 60 * 60
    },
    200,
    origin
  );
}


// ============================================================
// AUTH CHECK
// ============================================================

async function requireAuth(request, env) {

  const header =
    request.headers.get("Authorization") || "";

  const token =
    header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

  if (
    !token ||
    !(await verifyToken(
      token,
      env.SESSION_SECRET
    ))
  ) {
    throw new HttpError(
      "Neplatné nebo prošlé přihlášení.",
      401
    );
  }
}


// ============================================================
// ERROR CLASS
// ============================================================

class HttpError extends Error {

  constructor(message, status) {
    super(message);
    this.status = status;
  }

}


// ============================================================
// LOAD PRODUCTS FOR ADMIN
// ============================================================

async function handleAdminData(env, origin) {

  const products =
    await getGitHubData(env);

  let imeiMap = {};

  if (env.IMEI_KV) {

    imeiMap =
      (await env.IMEI_KV.get(
        "imei-map",
        "json"
      )) || {};

  }

  const result =
    products.map(product => ({
      ...product,
      imei:
        imeiMap[String(product.id)] || ""
    }));

  return json(
    {
      products: result
    },
    200,
    origin
  );
}


// ============================================================
// SAVE PRODUCTS
// ============================================================

async function handleSave(
  request,
  env,
  origin
) {

  const body =
    await request.json().catch(() => ({}));

  const incoming =
    Array.isArray(body.products)
      ? body.products
      : null;

  if (!incoming) {

    return json(
      {
        error:
          "Očekáváno pole products."
      },
      400,
      origin
    );

  }

  validateProducts(incoming);


  // ==========================================================
  // IMEI
  // ==========================================================

  const imeiMap = {};

  for (const product of incoming) {

    const imei =
      String(product.imei || "")
        .replace(/\D/g, "");

    if (imei) {

      if (!/^\d{15}$/.test(imei)) {

        return json(
          {
            error:
              `Neplatné IMEI u produktu ${product.id}.`
          },
          400,
          origin
        );

      }

      imeiMap[String(product.id)] =
        imei;
    }
  }


  // Kontrola unikátnosti IMEI

  const imeis =
    Object.values(imeiMap);

  if (
    new Set(imeis).size !==
    imeis.length
  ) {

    return json(
      {
        error:
          "IMEI musí být jedinečné."
      },
      400,
      origin
    );

  }


  // ==========================================================
  // REMOVE IMEI FROM PUBLIC DATA
  // ==========================================================

  const cleanProducts =
    incoming.map(product => {

      const copy = {
        ...product
      };

      delete copy.imei;


      if (
        Array.isArray(copy.images)
      ) {

        copy.images =
          copy.images.filter(
            image =>
              typeof image === "string" &&
              image.trim() &&
              !image.startsWith("data:")
          );

      } else {

        copy.images = [];

      }


      copy.img =
        copy.images[0] ||
        copy.img ||
        "";

      return copy;

    });


  // ==========================================================
  // SAVE DATA.JSON TO GITHUB
  // ==========================================================

  await putGitHubFile(
    env,
    "data.json",
    JSON.stringify(
      cleanProducts,
      null,
      2
    ) + "\n",
    `Aktualizace katalogu ${new Date().toISOString()}`
  );


  // ==========================================================
  // SAVE IMEI TO CLOUDFLARE KV
  // ==========================================================

  if (!env.IMEI_KV) {

    throw new HttpError(
      "Není nastaven Cloudflare KV binding IMEI_KV.",
      500
    );

  }

  await env.IMEI_KV.put(
    "imei-map",
    JSON.stringify(imeiMap)
  );


  // Vrátíme data administraci

  const result =
    cleanProducts.map(product => ({
      ...product,
      imei:
        imeiMap[String(product.id)] || ""
    }));


  return json(
    {
      ok: true,
      products: result
    },
    200,
    origin
  );
}


// ============================================================
// IMAGE UPLOAD
// ============================================================

async function handleImageUpload(
  request,
  env,
  origin
) {

  const body =
    await request.json().catch(() => ({}));

  const filename =
    sanitizeFilename(
      body.filename || ""
    );

  const data =
    String(body.data || "");


  if (
    !filename ||
    !data.startsWith("data:")
  ) {

    return json(
      {
        error:
          "Neplatný obrázek."
      },
      400,
      origin
    );

  }


  const match =
    data.match(
      /^data:([^;]+);base64,(.+)$/
    );


  if (!match) {

    return json(
      {
        error:
          "Neplatný formát obrázku."
      },
      400,
      origin
    );

  }


  const mime =
    match[1];

  const base64 =
    match[2];


  if (
    !/^image\/(jpeg|jpg|png|webp)$/i.test(mime)
  ) {

    return json(
      {
        error:
          "Povolené jsou JPG, PNG a WebP."
      },
      400,
      origin
    );

  }


  const binary =
    atob(base64);

  const bytes =
    Uint8Array.from(
      binary,
      c => c.charCodeAt(0)
    );


  // Maximální velikost 8 MB

  if (
    bytes.byteLength >
    8 * 1024 * 1024
  ) {

    return json(
      {
        error:
          "Obrázek je příliš velký."
      },
      400,
      origin
    );

  }


  let extension = "jpg";

  if (mime.includes("png")) {
    extension = "png";
  }

  if (mime.includes("webp")) {
    extension = "webp";
  }


  const path =
    `images/${filename.replace(
      /\.[^.]+$/,
      ""
    )}.${extension}`;


  const result =
    await putGitHubBytes(
      env,
      path,
      bytes,
      `Nahrání obrázku ${path}`
    );


  return json(
    {
      ok: true,
      path: path,
      url:
        result.content?.download_url ||
        `https://raw.githubusercontent.com/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/${env.GITHUB_BRANCH || "main"}/${path}`
    },
    200,
    origin
  );
}


// ============================================================
// LOAD DATA FROM GITHUB
// ============================================================

async function getGitHubData(env) {

  const file =
    await getGitHubFile(
      env,
      "data.json"
    );


  if (!file) {
    return [];
  }


  const decoded =
    decodeBase64Utf8(
      file.content
    );


  const data =
    JSON.parse(decoded);


  if (!Array.isArray(data)) {

    throw new Error(
      "data.json nemá správný formát."
    );

  }


  return data;
}


// ============================================================
// GET FILE FROM GITHUB
// ============================================================

async function getGitHubFile(
  env,
  path
) {

  const branch =
    env.GITHUB_BRANCH || "main";


  const url =
    `https://api.github.com/repos/` +
    `${env.GITHUB_OWNER}/` +
    `${env.GITHUB_REPO}/` +
    `contents/${encodePath(path)}` +
    `?ref=${encodeURIComponent(branch)}`;


  const response =
    await githubFetch(
      env,
      url
    );


  if (response.status === 404) {
    return null;
  }


  if (!response.ok) {

    const text =
      await response.text();

    throw new Error(
      `GitHub GET ${path} selhal (${response.status}): ${text.slice(0,500)}`
    );

  }


  return await response.json();
}


// ============================================================
// WRITE FILE TO GITHUB
// ============================================================

async function putGitHubFile(
  env,
  path,
  content,
  message
) {

  const bytes =
    new TextEncoder().encode(
      content
    );


  return await putGitHubBytes(
    env,
    path,
    bytes,
    message
  );
}


// ============================================================
// WRITE BINARY FILE TO GITHUB
// ============================================================

async function putGitHubBytes(
  env,
  path,
  bytes,
  message
) {

  const existing =
    await getGitHubFile(
      env,
      path
    );


  const body = {

    message: message,

    content:
      bytesToBase64(bytes),

    branch:
      env.GITHUB_BRANCH || "main"

  };


  if (existing?.sha) {

    body.sha =
      existing.sha;

  }


  const response =
    await githubFetch(
      env,

      `https://api.github.com/repos/` +
      `${env.GITHUB_OWNER}/` +
      `${env.GITHUB_REPO}/` +
      `contents/${encodePath(path)}`,

      {
        method: "PUT",

        body:
          JSON.stringify(body)
      }
    );


  if (!response.ok) {

    const text =
      await response.text();

    throw new Error(
      `GitHub PUT ${path} selhal (${response.status}): ${text.slice(0,500)}`
    );

  }


  return await response.json();
}


// ============================================================
// GITHUB REQUEST
// ============================================================

async function githubFetch(
  env,
  url,
  options = {}
) {

  const headers =
    new Headers(
      options.headers || {}
    );


  headers.set(
    "Accept",
    "application/vnd.github+json"
  );


  headers.set(
    "Authorization",
    `Bearer ${env.GITHUB_TOKEN}`
  );


  headers.set(
    "X-GitHub-Api-Version",
    "2022-11-28"
  );


  headers.set(
    "User-Agent",
    "bazar-admin-worker"
  );


  if (options.body) {

    headers.set(
      "Content-Type",
      "application/json"
    );

  }


  return fetch(
    url,
    {
      ...options,
      headers
    }
  );
}


// ============================================================
// VALIDATE PRODUCTS
// ============================================================

function validateProducts(
  products
) {

  const ids =
    new Set();


  for (const product of products) {

    if (
      !product ||
      product.id === undefined ||
      !product.title ||
      !product.brand
    ) {

      throw new HttpError(
        "Každý produkt musí mít ID, název a značku.",
        400
      );

    }


    const id =
      String(product.id);


    if (ids.has(id)) {

      throw new HttpError(
        `Duplicitní ID produktu: ${id}`,
        400
      );

    }


    ids.add(id);


    if (
      Array.isArray(product.images)
    ) {

      for (
        const image
        of product.images
      ) {

        if (
          typeof image !== "string" ||
          image.startsWith("data:")
        ) {

          throw new HttpError(
            "V datech nesmí zůstat data URI obrázek.",
            400
          );

        }

      }

    }

  }

}


// ============================================================
// FILENAME
// ============================================================

function sanitizeFilename(
  value
) {

  return String(value)

    .replace(
      /[^a-zA-Z0-9._-]+/g,
      "-"
    )

    .replace(
      /-+/g,
      "-"
    )

    .replace(
      /^\.+/,
      ""
    )

    .slice(
      0,
      140
    );
}


// ============================================================
// PATH ENCODING
// ============================================================

function encodePath(
  path
) {

  return path
    .split("/")
    .map(
      encodeURIComponent
    )
    .join("/");
}


// ============================================================
// BYTES -> BASE64
// ============================================================

function bytesToBase64(
  bytes
) {

  let binary = "";

  const chunk =
    0x8000;


  for (
    let i = 0;
    i < bytes.length;
    i += chunk
  ) {

    binary +=
      String.fromCharCode(
        ...bytes.subarray(
          i,
          i + chunk
        )
      );

  }


  return btoa(
    binary
  );
}


// ============================================================
// BASE64 UTF-8
// ============================================================

function decodeBase64Utf8(
  base64
) {

  const binary =
    atob(
      base64.replace(
        /\n/g,
        ""
      )
    );


  const bytes =
    Uint8Array.from(
      binary,
      c => c.charCodeAt(0)
    );


  return new TextDecoder()
    .decode(bytes);
}


// ============================================================
// BASE64URL
// ============================================================

function base64url(
  input
) {

  return btoa(input)

    .replace(
      /\+/g,
      "-"
    )

    .replace(
      /\//g,
      "_"
    )

    .replace(
      /=+$/,
      ""
    );
}


// ============================================================
// FROM BASE64URL
// ============================================================

function fromBase64url(
  input
) {

  const padded =
    input
      .replace(
        /-/g,
        "+"
      )
      .replace(
        /_/g,
        "/"
      );


  const padding =
    "=".repeat(
      (4 - padded.length % 4) % 4
    );


  return atob(
    padded + padding
  );
}


// ============================================================
// HMAC
// ============================================================

async function hmac(
  secret,
  value
) {

  const key =
    await crypto.subtle.importKey(

      "raw",

      new TextEncoder()
        .encode(secret),

      {
        name: "HMAC",
        hash: "SHA-256"
      },

      false,

      ["sign"]

    );


  return new Uint8Array(
    await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder()
        .encode(value)
    )
  );
}


// ============================================================
// CREATE SESSION TOKEN
// ============================================================

async function createToken(
  secret
) {

  if (!secret) {

    throw new Error(
      "SESSION_SECRET není nastavený."
    );

  }


  const payload = {

    exp:
      Math.floor(
        Date.now() / 1000
      ) + 8 * 60 * 60,

    iat:
      Math.floor(
        Date.now() / 1000
      )

  };


  const encodedPayload =
    base64url(
      JSON.stringify(
        payload
      )
    );


  const signatureBytes =
    await hmac(
      secret,
      encodedPayload
    );


  const signature =
    base64url(
      String.fromCharCode(
        ...signatureBytes
      )
    );


  return (
    encodedPayload +
    "." +
    signature
  );
}


// ============================================================
// VERIFY SESSION TOKEN
// ============================================================

async function verifyToken(
  token,
  secret
) {

  try {

    if (!secret) {
      return false;
    }


    const parts =
      token.split(".");


    if (
      parts.length !== 2
    ) {

      return false;

    }


    const payload =
      JSON.parse(
        fromBase64url(
          parts[0]
        )
      );


    if (
      !payload.exp ||
      payload.exp <
        Math.floor(
          Date.now() / 1000
        )
    ) {

      return false;

    }


    const expected =
      await hmac(
        secret,
        parts[0]
      );


    const suppliedBinary =
      fromBase64url(
        parts[1]
      );


    const supplied =
      Uint8Array.from(
        suppliedBinary,
        c => c.charCodeAt(0)
      );


    if (
      expected.length !==
      supplied.length
    ) {

      return false;

    }


    let diff = 0;


    for (
      let i = 0;
      i < expected.length;
      i++
    ) {

      diff |=
        expected[i] ^
        supplied[i];

    }


    return diff === 0;

  } catch {

    return false;

  }

}
