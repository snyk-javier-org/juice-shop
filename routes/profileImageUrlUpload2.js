/*
 * Copyright (c) 2014-2021 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

const fs = require('fs')
const models = require('../models/index')
const insecurity = require('../lib/insecurity')
const request = require('request')
const logger = require('../lib/logger')

module.exports = function profileImageUrlUpload2 () {
  return (req, res, next) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = insecurity.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        const imageRequest = request
          .get(url)
          .on('error', function (err) {
            models.User.findByPk(loggedInUser.data.id).then(user => { return user.update({ profileImage: url }) }).catch(error => { next(error) })
            logger.warn('Error retrieving user profile image: ' + err.message + '; using image link directly')
          })
          .on('response', function (res) {
            if (res.statusCode === 200) {
              const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
              imageRequest.pipe(fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`))
              models.User.findByPk(loggedInUser.data.id).then(user => { return user.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch(error => { next(error) })
            } else models.User.findByPk(loggedInUser.data.id).then(user => { return user.update({ profileImage: url }) }).catch(error => { next(error) })
          })
      } else {
        next(new Error('Blocked illegal activity by ' + req.connection.remoteAddress))
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
module.exports = function login2 () {
  function afterLogin (user, res, next) {
    verifyPostLoginChallenges(user)
    models.Basket.findOrCreate({ where: { UserId: user.data.id }, defaults: {} })
      .then(([basket]) => {
        const token = insecurity.authorize(user)
        user.bid = basket.id // keep track of original basket for challenge solution check
        insecurity.authenticatedUsers.put(token, user)
        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })
      }).catch(error => {
        next(error)
      })
  }

  return (req, res, next) => {
    verifyPreLoginChallenges(req)
    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${insecurity.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: true })
      .then((authenticatedUser) => {
        let user = utils.queryResultToJson(authenticatedUser)
        const rememberedEmail = insecurity.userEmailFrom(req)
        if (rememberedEmail && req.body.oauth) {
          models.User.findOne({ where: { email: rememberedEmail } }).then(rememberedUser => {
            user = utils.queryResultToJson(rememberedUser)
            utils.solveIf(challenges.loginCisoChallenge, () => { return user.data.id === users.ciso.id })
            afterLogin(user, res, next)
          })
        } else if (user.data && user.data.id && user.data.totpSecret !== '') {
          res.status(401).json({
            status: 'totp_token_required',
            data: {
              tmpToken: insecurity.authorize({
                userId: user.data.id,
                type: 'password_valid_needs_second_factor_token'
              })
            }
          })
        } else if (user.data && user.data.id) {
          afterLogin(user, res, next)
        } else {
          res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch(error => {
        next(error)
      })
  }

  function verifyPreLoginChallenges (req) {
    utils.solveIf(challenges.weakPasswordChallenge, () => { return req.body.email === 'admin@' + config.get('application.domain') && req.body.password === 'admin123' })
    utils.solveIf(challenges.loginSupportChallenge, () => { return req.body.email === 'support@' + config.get('application.domain') && req.body.password === 'J6aVjTgOpRs$?5l+Zkq2AYnCE@RF§P' })
    utils.solveIf(challenges.loginRapperChallenge, () => { return req.body.email === 'mc.safesearch@' + config.get('application.domain') && req.body.password === 'Mr. N00dles' })
    utils.solveIf(challenges.loginAmyChallenge, () => { return req.body.email === 'amy@' + config.get('application.domain') && req.body.password === 'K1f.....................' })
    utils.solveIf(challenges.dlpPasswordSprayingChallenge, () => { return req.body.email === 'J12934@' + config.get('application.domain') && req.body.password === '0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB' })
    utils.solveIf(challenges.oauthUserPasswordChallenge, () => { return req.body.email === 'bjoern.kimminich@gmail.com' && req.body.password === 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
  }

  function verifyPostLoginChallenges (user) {
    utils.solveIf(challenges.loginAdminChallenge, () => { return user.data.id === users.admin.id })
    utils.solveIf(challenges.loginJimChallenge, () => { return user.data.id === users.jim.id })
    utils.solveIf(challenges.loginBenderChallenge, () => { return user.data.id === users.bender.id })
    utils.solveIf(challenges.ghostLoginChallenge, () => { return user.data.id === users.chris.id })
    if (utils.notSolved(challenges.ephemeralAccountantChallenge) && user.data.email === 'acc0unt4nt@' + config.get('application.domain') && user.data.role === 'accounting') {
      models.User.count({ where: { email: 'acc0unt4nt@' + config.get('application.domain') } }).then(count => {
        if (count === 0) {
          utils.solve(challenges.ephemeralAccountantChallenge)
        }
      })
    }
  }
}
