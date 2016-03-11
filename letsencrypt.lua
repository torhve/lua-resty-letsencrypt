--
-- lua-resty-letsencrypt, by Tor Hveem
-- luacheck: globals ngx, ignore foo
--
-- See README.
--
--[[

Copyright (c) 2016 Tor Hveem
Copyright (c) 2016 Kim Alvefur

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

--]]

local ngx = ngx
local ssl = require 'ngx.ssl'
local http = require "resty.http" -- https://github.com/pintsized/lua-resty-http

local _M = {}

-- NGINX shared worker memory. in nginx.conf:  lua_shared_dict acme 512k
_M.ngx_mem = ngx.shared.acme

local tableHasValue = function(table, value)
    if(type(table) ~= 'table') then return end

    for _, v in next, table do
        if(v == value) then return true end
    end
end

local safeFormat = function(format, ...)
    if(select('#', ...) > 0) then
        local success, message = pcall(string.format, format, ...)
        if(success) then
            return message
        end
    else
        return format
    end
end

local log = function(s, ...)
    ngx.log(ngx.ERR, '___***___: '..safeFormat(s, ...))
end

-- HTTP request
local http_request = function(uri, post_body)
    local httpc = http.new()
    httpc:set_timeout(5000)
    local method = "POST"
    if not post_body then
        method = 'GET'
    end
    log('HTTP request: %s, method: %s, body: %s', uri, method, post_body)
    local res, err = httpc:request_uri(uri, {
        method = method,
        body = post_body,
        ssl_verify = false,
    })

    if not res then
        return nil, 500, "failed to request: " .. tostring(err)
    end

    --log('HTTP requested finished: %s bytes, status: %s', #res.body, res.status)

    return res.body, tonumber(res.status), res.headers, tonumber(res.status)

end

local json = require 'cjson.safe'
-- Reimplement this to use internal nginx b64
package.preload['b64url'] = function()
    local encode = function(s)
        -- Help to base64 encode URL
        local b64map = {
            ['+'] = '-', ['/'] = '_', ['='] = '',
            ['-'] = '+', ['_'] = '/'
        }
        return ngx.encode_base64(s):gsub('[+/=]', b64map)
    end
    return {
        encode = encode
    }
end
local b64url = require'b64url'.encode
package.preload['acme.error'] = function()
    return {
        parse = function()
            local err_mt = {}

            function err_mt:__tostring()
                return ("%d{%s}%s"):format(self.status or -1, self.type, self.detail or "")
            end

            local function parse_error(err)
                local jerr = json.decode(err)
                if jerr then
                    return setmetatable(jerr, err_mt)
                end
                return err
            end
          return parse_error
        end
    }
end
local parse_error = require'acme.error'.parse

-- lua-jwc/jwk.lua
package.preload['jwk'] = function()
    local digest = require "openssl.digest"

    local function get_public_rsa(key)
        local key_n, key_e = key:getParameters("n", "e")
        return {
            kty = "RSA",
            n = b64url(key_n:tobin()),
            e = b64url(key_e:tobin())
        }
    end

    local key_type_map = {
        rsaEncryption = get_public_rsa
    }

    local function get_public(key)
        local get_pubkey = key_type_map[key:type()]
        if not get_pubkey then
            return nil, "unsupported-algorithm"
        end
        return get_pubkey(key)
    end

    local function thumbprint(key, hash_alg)
        local jwk_pub, err = get_public(key)
        if not jwk_pub then return nil, err; end

        local ordered = {}
        for k,v in pairs(jwk_pub) do
            table.insert(ordered, json.encode(k) .. ":" .. json.encode(v))
        end
        table.sort(ordered)
        local canonical = "{" .. table.concat(ordered, ",") .. "}"
        local hash = digest.new(hash_alg or "sha256")
        hash:update(canonical)
        return b64url(hash:final())
    end
    return {
        get_public = get_public,
        thumbprint = thumbprint
    }
end
local jwk = require "jwk"
-- lua-jwc/jws.lua
package.preload['jws'] = function()
    local digest = require "openssl.digest"
    -- Hash function -> key type -> "alg" parameter
    local hash_key_algorithm_map = {
        sha256 = {
            rsaEncryption = "RS256"; -- RSA-with-SHA2-256
        }
    }

    local hash_algorithm = "sha256"

    local algorithm_map = hash_key_algorithm_map[hash_algorithm]

    local function jws_sign(key, header, payload)
        local alg = algorithm_map[key:type()]
        if not alg then
            return nil, "unsupported-algorithm"
        end

        local jwk_pub, err = jwk.get_public(key)
        if not jwk_pub then return nil, err; end

        local encoded_payload = b64url(json.encode(payload))
        local protected_header = b64url(json.encode(header))

        local unprotected_header = {
            alg = alg,
            jwk = jwk_pub
        }

        local hash = digest.new(hash_algorithm)
        hash:update(protected_header .. "." .. encoded_payload)
        local signature = b64url(key:sign(hash))

        -- Flattened JSON Serialization
        return json.encode({
            payload = encoded_payload,
            protected = protected_header,
            header = unprotected_header,
            signature = signature
        })
    end

    return {
        sign = jws_sign
    }
end
local jws = require'jws'

-- http-01 acme challenge
local http_challenge = function()

    local function verify(account, host, token)

        local url = ("http://%s/.well-known/acme-challenge/%s"):format(host, token)
        local data = http_request(url)
        return data == account.get_key_authz(token)
    end

    local function describe(account, host, token)
        log("echo -n %q > /var/www/%s/%s", account.get_key_authz(token), host, token)
    end

    return {
        verify = verify,
        describe = describe,
    }

end

local pkey = require "openssl.pkey"
local x509 = require "openssl.x509"
local x509_name = require "openssl.x509.name"
local x509_csr = require "_openssl.x509.csr"

package.preload['acme.account'] = function()
    local function new(account_key, directory_url, https_request)
      if account_key == nil then
        account_key = pkey.new();
      elseif type(account_key) == "string" then
        local ok, key = pcall(pkey.new, account_key);
        if not ok then return ok, key; end
        account_key = key;
      end
      if not directory_url then
        directory_url = "https://acme-staging.api.letsencrypt.org/directory";
      end
      if not https_request then
        https_request = require "ssl.https".request;
      end

      local nonces = {
        pop = table.remove;
        push = table.insert;
      };

      local function decode(type, data)
        if type == "application/json" or (type and type:find"%+json") then
          return json.decode(data);
        end
        return data;
      end

      local function request(url, post_body)
        -- print("request", url, post_body)
        local response_body, code, headers, status = https_request(url, post_body);
        if code - (code % 100) ~= 200 then
          -- print(response_body);
          return nil, parse_error(response_body);
        end
        if headers["replay-nonce"] then
          nonces:push(1, headers["replay-nonce"]);
        end
        return {
          url = url;
          code = code;
          status = status;
          head = headers;
          body = decode(headers["content-type"], response_body);
        };
      end

      local directory;

      local function fetch_directory()
        directory = assert(request(directory_url).body);
        return directory;
      end

      local function get_directory()
        return directory or fetch_directory();
      end

      local function signed_request(url, obj)
        while not nonces[1] do
          fetch_directory(); -- need more nonces
        end
        return request(url, jws.sign(account_key, { nonce = nonces:pop() }, obj));
      end

      local function step(obj, url)
        if not url then
          if not directory then
            fetch_directory();
          end
          url = url or directory[obj.resource];
        end
        return signed_request(url, obj);
      end

      local function register(...)
        return step({ resource = "new-reg", contact = { ... }});
      end

      local function get_key_authz(token)
        return token .. "." .. jwk.thumbprint(account_key);
      end

      local function new_authz(identifier)
        return step({ resource = "new-authz", identifier = identifier });
      end

      local function new_dns_authz(name)
        return new_authz({ type = "dns", value = name });
      end

      local function poll_challenge(challenge)
        return step({
          resource = "challenge",
          type = challenge.type,
          keyAuthorization = get_key_authz(challenge.token);
        }, challenge.uri);
      end

      return {
        account_key = account_key;
        directory_url = directory_url;

        nonces = nonces;

        signed_request = signed_request;
        unsigned_request = request;
        get_key_authz = get_key_authz;
        get_directory = get_directory;
        step = step;

        register = register;
        new_authz = new_authz;

        new_dns_authz = new_dns_authz;
        poll_challenge = poll_challenge;
      };
    end

    return {
      new = new;
    };
end

local acme = require "acme.account"

package.preload['acme.datautil'] = function()
    local function loaddata(filename)
      local f, err = io.open(filename);
      if not f then return f, err; end
      local data = f:read("*a");
      f:close();
      return data, err;
    end

    local function savedata(filename, data)
      local scratch, ok = filename.."~";
      local f, err = io.open(scratch, "w");
      if not f then return nil, err; end
      ok, err = f:write(data);
      if ok then ok, err = f:flush(); end
      if not ok then
        f:close();
        os.remove(scratch);
        return ok, err;
      end
      ok, err = f:close();
      if not ok then
        os.remove(scratch);
        return ok, err;
      end
      return os.rename(scratch, filename);
    end

    local function loadjson(filename)
      local data, err = loaddata(filename);
      if data then
        data, err = json.decode(data);
      end
      return data, err;
    end

    local function savejson(filename, data)
      local bytes, err = json.encode(data);
      if not bytes then return bytes, err; end
      return savedata(filename, bytes);
    end

    return {
      load = loaddata;
      save = savedata;

      loadjson = loadjson;
      savejson = savejson;
    }
end

local file = require "acme.datautil"

file.exists = function(fname)
    local f = io.open(fname, "r")
    if f ~= nil then io.close(f) return true else return false end
end
-- Rudimentary lock helper on top og ngx.shared.DICT
local Lock = {}
Lock.new = function(timeout)
    if not timeout then
        timeout = 10
    end

    local dict = ngx.shared.acme
    if not dict then
        return nil, 'nginx shared dict not found'
    end

    return setmetatable({
        timeout=timeout,
        dict=dict
    }, { __index = Lock })
end

Lock.lock = function(self, name)
    local key = '_lock:'..name
    local exptime = self.timeout
    local dict = self.dict
    local ok, err = dict:add(key, true, exptime)
    if ok then
        return 0
    end

    if err ~= "exists" then
        return nil, err
    end
    -- Lock in use by someone else

    local elapsed = 0
    local step = 0.001
    local max_step = 0.5
    local ratio = 2
    while exptime > 0 do
        if step > exptime then
            step = exptime
        end

        ngx.sleep(step)
        elapsed = elapsed + step
        exptime = exptime - step
        -- luacheck: ignore ok err
        local ok, err = dict:add(key, true, self.timeout)
        if ok then
            return elapsed
        end

        if err ~= "exists" then
            return nil, err
        end

        if exptime <= 0 then
            break
        end

        step = step * ratio
        if step <= 0 then
            step = 0.001
        end

        if step > max_step then
            step = max_step
        end
    end
    return nil, 'timeout'
end

Lock.unlock = function(self, name)
    local key = '_lock:'..name
    local dict = self.dict
    local ok, err = dict:delete(key)
    if not ok then
        return nil, err
    end

    return 1
end

-- A caching file loader
file.load = function(fname)
    local cache = ngx.shared.acme
    local key = '_fcache:'..fname

    local val, err = cache:get(key)
    if not val then
        local lock = Lock.new()
        lock:lock(key)
        -- Check again
        val, err = cache:get(key)
        if val then
            lock:unlock(key)
            return val, err
        end
        local f
        f, err = io.open(fname)
        if not f then
            lock:unlock(key)
            return f, err
        end
        local data = f:read("*a")
        f:close()
        -- Update cache
        cache:set(key, data)
        lock:unlock(key)
        return data, err
    end
    return val, err
end


_M.new = function(conf)
    local account_file = conf.root..'account.json'
    local account_data = file.loadjson(account_file)
    local key_file = account_file:gsub("%.json$", "") .. ".key"
    local lock = Lock.new()
    -- Flush caches, this makes it possible recheck cert files and reload files
    -- on nginx reload, since init_by_lua is ran.
    ngx.shared.acme:flush_all()
    return setmetatable({
        conf = conf,
        account_file = account_file,
        account_data = account_data,
        key_file = key_file,
        lock = lock,
    }, { __index = _M })
end

_M.init_account = function(self)
    local account
    local elapsed, err = self.lock:lock('account')
    if elapsed > 0 then
        log('Account lock took: %s', elapsed)
    end
    if err then
        log('Account lock error: %s', err)
    end


    if not self.account_data then
        log('Registering new account')
        -- Set account creation lock
        self.account_data = {}

        local key = file.load(self.key_file)
        if not key then
            key = pkey.new{ bits = 4096 }
            file.save(self.key_file, key:toPEM("private"))
        end

        self.account_data.directory_url = self.conf.directory_url
        account = assert(acme.new(key, self.conf.directory_url, http_request))
        -- luacheck: ignore err
        local reg, err = account.step({resource='new-reg', contact={self.conf.contact}, agreement=self.conf.agreement})
        --local reg, err = account.step({resource = 'new-reg', agreement = agreement})
        if not reg then
            log('Error registering with ACME server: %s',tostring(err()))
        else
            log('Registration OK!')
            self.account_data.reg = reg
        end
        file.savejson(self.account_file, self.account_data)
    end
    if self.account then
        account = self.account
    else -- Load from file
        account = assert(acme.new(assert(file.load(self.key_file)), self.account_data.directory_url, http_request))
    end

    self.account = account

    self.hosts = self.account_data.hosts
    if not self.hosts then
        self.hosts = {}
        self.account_data.hosts = self.hosts
    end

    self.lock:unlock('account')

    return account, self.hosts
end

_M.get_intermediate = function(self)
    -- Unused function for now, as the .crt contains the intermediate.
    local fname = self.conf.root.."intermediate.crt"
    local data = file.load(fname)
    if not data then
        local req, _ = http_request'http://cert.int-x1.letsencrypt.org/'
        if req then
            data = req
            file.save(fname, data)
            log('Saved intermediate cert to: %s', fname)
        end
    end
    return data
end

_M.cert_for_host = function(self, host)
    local account, hosts = self:init_account()
    local authz = hosts[host]
    if not authz then
        local cert = file.load(self.conf.root..host..".der")
        if cert then
            cert = x509.new(cert, "DER")
            -- luacheck: ignore issued
            local issued, expires = assert(cert:getLifetime())

            --log(os.date("Issued:  %F", issued))
            --log(os.date("Expires: %F", expires))
            if os.time() + (86400 * 7 * 3) > expires then
                log("Renewal time")
                cert = false
            end
        end

        if not cert then
            log('No cert for hostname: %s. Creating authz.', host)
            -- Create new authz request
            local newdata, err = account.new_dns_authz(host)
            if not newdata then
                log(tostring(err), "")
            else
                hosts[host], authz = newdata, newdata
            end
        end
    else
        authz.need_update = true
    end

    if authz then
        while authz.body.status == "pending" do
            if authz.need_update then
                log("Updating authz...")
                local updated, err = account.unsigned_request(authz.head.location or authz.url)
                if not updated then
                    log("Failed to update authz: %s", tostring(err))
                    break
                else
                    hosts[host], authz = updated, updated
                end
            end
            -- We only support 'http-01' in this script
            for i, challenge in ipairs(authz.body.challenges) do
                if challenge.type == "http-01" then
                    local challenge_test = http_challenge()
                    local key_authz = account.get_key_authz(challenge.token)
                    if challenge.type == "http-01" then
                        self.ngx_mem:set('token:'..challenge.token, key_authz)
                    end

                    while challenge.status == "pending" and not challenge.keyAuthorization do
                        log("Checking " .. tostring(challenge.type) .. " challenge...")
                        if challenge_test.verify(account, host, challenge.token) then
                            log("Polling " .. challenge.type.. " challenge...")
                            local poll, err = account.step({
                                resource = "challenge",
                                type = challenge.type,
                                keyAuthorization = key_authz,
                            }, challenge.uri)
                            if not poll then
                                log(tostring(err))
                                authz.need_update = true
                                break
                            else
                                if challenge.status ~= poll.body.status then
                                    authz.need_update = true
                                end
                                authz.body.challenges[i] = poll.body
                                challenge = poll.body
                            end
                        else
                            log("Incomplete ".. challenge.type.." challenge:")
                            challenge_test.describe(account, host, challenge.token)
                            assert(file.savejson(self.account_file, self.account_data))
                            log("Complete this challenge and run this again")
                        end
                    end

                    while challenge.keyAuthorization and challenge.status == "pending" do
                        ngx.sleep(0.5)
                        local updated_challenge, err = account.unsigned_request(challenge.uri)
                        if updated_challenge then
                            authz.body.challenges[i] = updated_challenge.body
                            challenge = updated_challenge.body
                            if challenge.status ~= "pending" then
                                authz.need_update = true
                            end
                        else
                            log("Failed to poll challenge: " .. tostring(err))
                            break
                        end
                    end

                    if not authz.combinations then
                        break
                    end
                    local allvalid = false
                    for _, combo in ipairs(authz.combinations) do
                        allvalid = true
                        for _, challenge_id in ipairs(combo) do
                            -- 0-based indexing... silly JSON
                            if authz.challenges[challenge_id+1].status ~= "valid" then
                                allvalid = false
                                break
                            end
                        end
                    end
                    if allvalid then break end
                end
            end

            assert(file.savejson(self.account_file, self.account_data))
        end

        if authz.body.status == "valid" then
            log("Authorized, preparing CSR...")
            local csr = file.load(self.conf.root..host..".csr")
            if csr then
                csr = x509_csr.new(csr)
            else
                csr = x509_csr.new()

                local name = x509_name.new()
                name:add("CN", host)
                csr:setSubject(name)

                local key = file.load(self.conf.root..host..".key")
                if key then
                    key = pkey.new(key)
                else
                    log("Generating new RSA key...")
                    key = pkey.new({ bits = 4096 })
                    file.save(self.conf.root..host..".key", key:toPEM("private"))
                end
                csr:setPublicKey(key)
                csr:sign(key)

                file.save(self.conf.root..host..".pub", key:toPEM("public"))
                file.save(self.conf.root..host..".csr", csr:tostring())
            end

            local cert, err = account.step({
                resource = "new-cert",
                csr = b64url(csr:tostring("DER")),
            })

            if cert then
                if cert.head["content-type"] == "application/pkix-cert" then
                    file.save(self.conf.root..host..".der", cert.body)
                    local pem_crt = tostring(x509.new(cert.body, "DER"))
                    for link, rel in string.gmatch(cert.head.link or "", "<(.-)>;rel=\"(.-)\"") do
                        if rel == "up" then
                            local up = account.unsigned_request(link)
                            if up then
                                pem_crt = pem_crt .. tostring(x509.new(up.body, "DER"))
                            end
                        end
                    end
                    if file.exists(host..".crt") then
                        os.rename(host..".crt", host..".crt.old")
                    end
                    file.save(self.conf.root..host..".crt", pem_crt)
                    cert.body = nil
                end
                hosts[host] = nil
                file.savejson(self.conf.root..host..".json", cert)
            else
                log("Error requesting certificate: %s", tostring(err))
            end
        end
    end
    assert(file.savejson(self.account_file, self.account_data))
end

_M.ssl = function(self)
    local ssl_hostname = ssl.server_name() or ''

    -- Check if ssl_hostname is in list of allowed domains
    if not tableHasValue(self.conf.domains, ssl_hostname) then
        log('Request for non-configured domain: %s. Returning fallback cert.', ssl_hostname)
        return
    end

    local ok, err, _

    -- Check cache for existing cert for this hostname
    -- if not try to generate.

    -- TODO: do expiry check every x number of requests, since right now the
    -- check would only be ran on nginx restart

    -- Check and generate certs behind lock, so we don't run multiple session
    -- to letsencrypt at the same time.
    self.lock:lock('cert:'..ssl_hostname)
    ok, err = pcall(function() -- Run in a protected call in case of any errors
        self:cert_for_host(ssl_hostname)
    end)
    self.lock:unlock('cert:'..ssl_hostname)
    if not ok then
        log('Unable to generate cert: %s', err)
        debug.traceback()
        return
    end

    -- clear the fallback certificates and private keys
    -- set by the ssl_certificate and ssl_certificate_key
    -- directives
    ok, _ = ssl.clear_certs()
    if not ok then
        log"failed to clear existing (fallback) certificates"
        return ngx.exit(ngx.ERROR)
    end

    local pem = file.load(self.conf.root..ssl_hostname..'.crt')

    local der_chain
    -- TODO: cache the pem_to_der conversion
    -- reason we don't use the DER-file directly is that .crt contain
    -- the intermediate certificate.
    -- See also: https://github.com/openresty/lua-resty-core/blob/master/lib/ngx/ssl.md#cert_pem_to_der
    der_chain, err = ssl.cert_pem_to_der(pem)
    if not der_chain then
        log('Error %s, while converting pem chain to der', err)
    end

    ok, err = ssl.set_der_cert(der_chain)
    if not ok then
        log('Error %s, while setting der cert', err)
    end

    local pkey_filename = self.conf.root..ssl_hostname..'.key'
    local der_priv
    der_priv, err = ssl.priv_key_pem_to_der(file.load(pkey_filename))
    if not der_priv then
        log('Error %s, while converting priv key with filename %s', err, pkey_filename)
    end

    ok, err = ssl.set_der_priv_key(der_priv)
    if not ok then
        log('Error %s, while setting der key with filename %s', err, pkey_filename)
    end

    -- TODO: check that we actually managed to read valid certs and set them,
    -- if we didn't we should read back the fallback certs.

    -- End Nginx phase.
    return
end

local challenge = function(self)
    -- If it's content phase. Check if we should return challenge.
    local token = ngx.var.request_uri:match('.well%-known/acme%-challenge/(.*)')
    if not token then
        ngx.exit(404)
    end
    log('Getting request for token: %s', token)
    local authz = self.ngx_mem:get('token:'..token)
    if not authz then
        ngx.exit(404)
    else
        ngx.header.content_type = 'text/plain'
        ngx.print(authz)
        ngx.exit(200)
    end
end

local debug_output = function(self)

    local ssl_hostname = ssl.server_name() or ''
    -- Debug handler:
    -- Set default content type
    ngx.header.content_type = 'text/plain'
    ngx.say(ssl_hostname)
    ngx.say('Everything went better than expected!')
    if ssl_hostname ~= '' then
        local cert = file.load(self.conf.root..ssl_hostname..".der")
        if cert then
            cert = x509.new(cert, "DER")
            local issued, expires = assert(cert:getLifetime())

            ngx.say(os.date("Issued:  %F", issued))
            ngx.say(os.date("Expires: %F", expires))
        else
            ngx.say('Unable to load cert')
        end
    end
end

_M.challenge = challenge
_M.debug_output = debug_output

return _M
