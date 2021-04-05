const api = require('./util/api');
const wrapAsync = require('./util/wrapAsync');
const hmac = require('hmac-auth-express');
const { HMACAuthError } = require('hmac-auth-express/src/errors');

function respond(res, err, data) {
  if (err && !err.httpStatus) {
    res.status(503);
  }
  if (err && err.httpStatus) {
    res.status(err.httpStatus);
    delete err.httpStatus;
  }
  if (err) {
    err.error = true;
  }
  if (!err && data !== undefined) {
    if (typeof data === 'boolean') {
      data = { data: data };
    }
  }
  let out = err !== undefined && err !== null ? err : data;
  out = out === undefined ? {} : out;
  res.send(out);
}

const parseBody = body => {
  let out;
  try {
    if (typeof body === 'string') {
      return JSON.parse(body);
    }

    let booleans = ['passwordExpires', 'enabled'];
    for (const name in body) {
      if (booleans.indexOf(name) > -1) {
        body[name] =
          body[name] === 'true'
            ? true
            : body[name] === 'false'
            ? false
            : body[name];
      }
    }
    return body;
  } catch (e) {
    return body;
  }
};

module.exports = (app, config, ad) => {
  const start = new Date();
  app.get('/status', async (req, res) => {
    let uptime = new Date() - start;
    res.send({ online: true, uptime });
  });

  app.use(
    '/',
    hmac(config.secret, {
      algorithm: 'sha512',
      identifier: 'APP',
      header: 'authorization',
      maxInterval: 600
    })
  );
  // express' error handler
  app.use((error, req, res, next) => {
    // check by error instance
    if (error instanceof HMACAuthError) {
      res.status(401).json({
        error: 'Invalid request',
        info: error.message
      });
    }
  });

  app.get('/users', async (req, res) => {
    const filter = api.parseQuery(req.query);
    let [error, response] = await wrapAsync(ad.user().get(filter));
    respond(res, error, response);
  });

  app.post('/users', async (req, res) => {
    req.body = parseBody(req.body);
    let [error, response] = await wrapAsync(ad.user().add(req.body));
    respond(res, error, response);
  });

  app.get('/users/:user', async (req, res) => {
    const user = req.params.user;
    const config = api.parseQuery(req.query);
    let [error, response] = await wrapAsync(ad.user(user).get(config));
    respond(res, error, response);
  });

  app.get('/users/:user/exists', async (req, res) => {
    const user = req.params.user;
    let [error, response] = await wrapAsync(ad.user(user).exists());
    respond(res, error, response);
  });

  app.get('/users/:user/member-of/:group', async (req, res) => {
    const user = req.params.user;
    const group = req.params.group;
    let [error, response] = await wrapAsync(ad.user(user).isMemberOf(group));
    respond(res, error, response);
  });

  app.post('/users/:user/authenticate', async (req, res) => {
    req.body = parseBody(req.body);
    const user = req.params.user;
    const pass = req.body.pass || req.body.password;
    let [error, response] = await wrapAsync(ad.user(user).authenticate(pass));
    respond(res, error, response);
  });

  app.put('/users/:user', async (req, res) => {
    req.body = parseBody(req.body);
    const user = req.params.user;
    let [error, response] = await wrapAsync(ad.user(user).update(req.body));
    response = !error ? { success: true } : response;
    error = error ? Object.assign({ success: false }, error) : error;
    respond(res, error, response);
  });

  app.put('/users/:user/password', async (req, res) => {
    req.body = parseBody(req.body);
    const user = req.params.user;
    const pass = req.body.pass || req.body.password;
    let [error, response] = await wrapAsync(ad.user(user).password(pass));
    response = !error ? { success: true } : response;
    error = error ? Object.assign({ success: false }, error) : error;
    respond(res, error, response);
  });

  app.put('/users/:user/password-never-expires', async (req, res) => {
    req.body = parseBody(req.body);
    const user = req.params.user;
    let [error, response] = await wrapAsync(
      ad.user(user).passwordNeverExpires()
    );
    response = !error ? { success: true } : response;
    error = error ? Object.assign({ success: false }, error) : error;
    respond(res, error, response);
  });

  app.put('/users/:user/password-expires', async (req, res) => {
    req.body = parseBody(req.body);
    const user = req.params.user;
    let [error, data] = await wrapAsync(ad.user(user).passwordExpires());
    let response = !error ? { success: true } : undefined;
    respond(res, error, response);
  });

  app.put('/users/:user/enable', async (req, res) => {
    req.body = parseBody(req.body);
    const user = req.params.user;
    let [error, data] = await wrapAsync(ad.user(user).enable());
    let response = !error ? { success: true } : undefined;
    respond(res, error, response);
  });

  app.put('/users/:user/disable', async (req, res) => {
    req.body = parseBody(req.body);
    const user = req.params.user;
    let [error, data] = await wrapAsync(ad.user(user).disable());
    let response = !error ? { success: true } : undefined;
    respond(res, error, response);
  });

  app.put('/users/:user/move', async (req, res) => {
    req.body = parseBody(req.body);
    const user = req.params.user;
    const location = req.body.location;
    let [error, response] = await wrapAsync(ad.user(user).move(location));
    respond(res, error, response);
  });

  app.put('/users/:user/unlock', async (req, res) => {
    req.body = parseBody(req.body);
    const user = req.params.user;
    let [error, data] = await wrapAsync(ad.unlockUser(user));
    let response = !error ? { success: true } : undefined;
    respond(res, error, response);
  });

  app.delete('/users/:user', async (req, res) => {
    const user = req.params.user;
    let [error, response] = await wrapAsync(ad.user(user).remove());
    respond(res, error, response);
  });

  app.get('/group', async (req, res) => {
    const config = api.parseQuery(req.query);
    let [error, response] = await wrapAsync(ad.group().get(config));
    respond(res, error, response);
  });

  app.post('/group', async (req, res) => {
    let [error, response] = await wrapAsync(ad.group().add(req.body));
    respond(res, error, response);
  });

  app.get('/group/:group', async (req, res) => {
    const group = req.params.group;
    const config = api.parseQuery(req.query);
    let [error, response] = await wrapAsync(ad.group(group).get(config));
    respond(res, error, response);
  });

  app.get('/group/:group/exists', async (req, res) => {
    const group = req.params.group;
    let [error, response] = await wrapAsync(ad.group(group).exists());
    respond(res, error, response);
  });

  app.post('/group/:group/users/:user', async (req, res) => {
    const group = req.params.group;
    const user = req.params.user;
    let [error, response] = await wrapAsync(ad.user(user).addToGroup(group));
    response = !error ? { success: true } : response;
    respond(res, error, response);
  });

  app.delete('/group/:group/users/:user', async (req, res) => {
    const group = req.params.group;
    const user = req.params.user;
    let [error, response] = await wrapAsync(
      ad.user(user).removeFromGroup(group)
    );
    response = !error ? { success: true } : response;
    respond(res, error, response);
  });

  app.delete('/group/:group', async (req, res) => {
    const group = req.params.group;
    let [error, response] = await wrapAsync(ad.group(group).remove());
    respond(res, error, response);
  });

  app.get('/ou', async (req, res) => {
    const filters = api.parseQuery(req.query);
    let [error, response] = await wrapAsync(ad.ou().get(filters));
    respond(res, error, response);
  });

  app.post('/ou', async (req, res) => {
    let [error, response] = await wrapAsync(ad.ou().add(req.body));
    respond(res, error, response);
  });

  app.get('/ou/:ou', async (req, res) => {
    let ou = req.params.ou;
    const filters = api.parseQuery(req.query);
    let [error, response] = await wrapAsync(ad.ou(ou).get(filters));
    respond(res, error, response);
  });

  app.get('/ou/:ou/exists', async (req, res) => {
    const ou = req.params.ou;
    let [error, response] = await wrapAsync(ad.ou(ou).exists());
    respond(res, error, response);
  });

  app.delete('/ou/:ou', async (req, res) => {
    const ou = req.params.ou;
    let [error, response] = await wrapAsync(ad.ou(ou).remove());
    respond(res, error, response);
  });

  app.get('/other', async (req, res) => {
    const config = api.parseQuery(req.query);
    let [error, response] = await wrapAsync(ad.other().get(config));
    respond(res, error, response);
  });

  app.get('/all', async (req, res) => {
    const config = api.parseQuery(req.query);
    let [error, response] = await wrapAsync(ad.all().get(config));
    respond(res, error, response);
  });

  app.get('/find/:filter', async (req, res) => {
    const filter = req.params.filter;
    const config = api.parseQuery(req.query);
    let [error, response] = await wrapAsync(ad.find(filter, config));
    respond(res, error, response);
  });
};
