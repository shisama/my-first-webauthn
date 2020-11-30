/*
 * @license
 * Copyright 2019 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */
export const _fetch = async (path, payload = "") => {
  const headers = {
    "X-Requested-With": "XMLHttpRequest"
  };
  if (payload && !(payload instanceof FormData)) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(payload);
  }
  const res = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: headers,
    body: payload
  });
  if (res.status === 200) {
    // Server authentication succeeded
    return res.json();
  } else {
    // Server authentication failed
    const result = await res.json();
    throw result.error;
  }
};

// TODO (1): Register a credential using a fingerprint
// 1. Create `registerCredential()` function
// 2. Obtain the challenge and other options from server endpoint: `/auth/registerRequest`
// 3. Create a credential
// 4. Register the credential to the server endpoint: `/auth/registerResponse`
export const registerCredential = async () => {
  const opts = {
    // アテステーション伝達の優先度 none(default), indirect, direct
    attestation: "none",
    authenticatorSelection: {
      // 利用可能な認証器をフィルタ
      //   platform: プラットフォームの認証器
      //   cross-platform: ローミング認証器
      authenticatorAttachment: "platform",

      // 認証器の端末上のユーザー検証。
      // 指紋認証や画面ロック認証が必要な場合はrequiredを設定
      //   required: 必須
      //   preferred: 好ましい
      //   discourage: 回避
      userVerification: "required",

      // 作成したクレデンシャルを将来のアカウント選択UIで使用できるようにする場合はtrue
      requireResistantKey: false
    }
  };
  // サーバーからチャレンジとその他のオプションを取得
  const options = await _fetch("/auth/registerRequest", opts);

  // サーバーから取得したオプションをバイナリーに変換する
  // HTTPプロトコルを通過する際、文字列にエンコードして送信されるため
  options.user.id = base64url.decode(options.user.id);
  options.challenge = base64url.decode(options.challenge);
  if (options.excludeCredentials) {
    for (let cred of options.excludeCredentials) {
      cred.id = base64url.decode(cred.id);
    }
  }

  // 新しいクレデンシャルを作る。ブラウザーが認証器と対話し、
  // 指紋認証センサーまたは画面ロックを使用してユーザーのアイデンティティを検証
  const cred = await navigator.credentials.create({
    publicKey: options
  });

  // クレデンシャルのバイナリパラメータをエンコードして、
  // 文字列としてサーバーに送信できるようにする
  const credential = {};
  credential.id = cred.id;
  credential.rawId = base64url.encode(cred.rawId);
  credential.type = cred.type;
  if (cred.response) {
    const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
    const attestationObject = base64url.encode(cred.response.attestationObject);
    credential.response = {
      clientDataJSON,
      attestationObject
    };
  }

  // ユーザーが戻ってきたときに認証に使用できるようにクレデンシャルIDをローカルに保存
  localStorage.setItem("credId", credential.id);

  // クレデンシャルのオブジェクトをサーバーに送信して登録
  return await _fetch("/auth/registerResponse", credential);
};

// TODO (2): Build the UI to register, get and remove credentials
// 3. Remove the credential: `removeCredential()`
export const unregisterCredential = async credId => {
  localStorage.removeItem("credId");
  return _fetch(`/auth/removeKey?credId=${encodeURIComponent(credId)}`);
};

// TODO (3): Authenticate the user with a fingerprint
// 1. Create `authetnicate()` function
// 2. Obtain the challenge and other options from server
// 3. Locally verify the user and get a credential
// 4. Verify the credential: `/auth/signinResponse`
export const authenticate = async () => {
  const opts = {};

  let url = "/auth/signinRequest";
  // ローカルにクレデンシャルIDが保存されている場合はそれをクエリパラメータに使用
  const credId = localStorage.getItem("credId");
  if (credId) {
    url += `?credId=${encodeURIComponent(credId)}`;
  }
  // サーバーからチャレンジとその他のオプションを取得する
  const options = await _fetch(url, opts);

  // 渡されたクレデンシャルIDと一致するものが見つからなかった場合、
  // allowCredentialsは空の配列になる
  // 見つかった場合は一つのオブジェクトを含む配列になっている
  // 空の場合はWebAuthnをスキップする
  if (options.allowCredentials.length === 0) {
    console.info("No registered credentials found.");
    return Promise.resolve(null);
  }

  // 端末上で認証いｓ、クレデンシャルを取得する
  options.challenge = base64url.decode(options.challenge);

  for (let cred of options.allowCredentials) {
    cred.id = base64url.decode(cred.id);
  }

  // 指紋センサーまたは画面ロックを使用してユーザーのアイデンティティを検証
  const cred = await navigator.credentials.get({
    publicKey: options
  });

  const credential = {};
  credential.id = cred.id;
  credential.type = cred.type;
  credential.rawId = base64url.encode(cred.rawId);

  if (cred.response) {
    const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
    const authenticatorData = base64url.encode(cred.response.authenticatorData);
    const signature = base64url.encode(cred.response.signature);
    const userHandle = base64url.encode(cred.response.userHandle);
    credential.response = {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle
    };
  }
  
  return await _fetch(`/auth/signinResponse`, credential);
};
