var cookieParser = require('cookie-parser')
var csrf = require('csurf')
var bodyParser = require('body-parser')
var express = require('express')
var request = require('supertest')
var assert = require('assert')

var CSRF_ERROR = 'form tampered with';

var app = express()
app.use(bodyParser.urlencoded({
  extended: false
}))
app.use(cookieParser())
app.use(csrf({
  cookie: true
}))

app.get('/token', getToken)
app.post('/post', post)
app.use(function csrfError(err, req, res, next) {
  if (err.code !== 'EBADCSRFTOKEN') {
    next(err);
  } else {
    res.status(err.status)
    res.send(CSRF_ERROR)
  }
})
app.use(function generalError(err, req, res, next){
  res.status(err.status || 500)
  res.send(err.message)
});

function getToken(req, res, next) {
  res.send(req.csrfToken());
}

function post(req, res, next) {
  if (req.body.msg !== 'foo') {
    next(new Error('Invalid POST'))
  } else {
    res.send({
      ok: true
    });
  }
}

describe('CSRF ', function() {
  var token;
  var agent = request.agent(app)
  it(' ...capture token', function(done) {
    agent.get('/token')
      .expect(function(res) {
        token = res.text;
      })
      .end(done)
  });

  it('should be able to POST with token', function(done) {
    agent.post('/post')
      .set('x-csrf-token', token)
      .type('form')
      .send({
        msg: 'foo'
      })
      .expect(200)
      .expect('{"ok":true}')
      .end(done)
  });

  it('should fail if not using agent', function(done) {
    request(app)
      .post('/post')
      .send({
        msg: 'foo'
      })
      .expect(403)
      .expect(CSRF_ERROR)
      .end(done)
  });
});
