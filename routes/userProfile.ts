/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'
import { challenges } from '../data/datacache'

import { UserModel } from '../models/user'
import challengeUtils = require('../lib/challengeUtils')
import config from 'config'
import * as utils from '../lib/utils'
import { AllHtmlEntities as Entities } from 'html-entities'
const security = require('../lib/insecurity')
const pug = require('pug')
const themes = require('../views/themes/themes').themes
const entities = new Entities()
const vm = require('vm')
const Handlebars = require('handlebars')

import escapeHtml from 'escape-html'
import path from 'path'

module.exports = function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = security.authenticatedUsers.get(req.cookies.token)
      if (!session) {
        return next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      }

      const user = await UserModel.findByPk(session.data.id)
      if (!user) { return next(new Error('User not found')) }

      /* 1. Безопасное имя пользователя */
      let username = escapeHtml(user.username ?? '')
      if (
        typeof user.username === 'string' &&
        user.username.match(/^#{.*}$/) &&
        utils.isChallengeEnabled(challenges.usernameXssChallenge)
      ) {
        /* Челлендж-флаг, но в шаблон идёт ЭКРАНИРОВАННАЯ строка */
        req.app.locals.abused_ssti_bug = true
        challengeUtils.solve(challenges.usernameXssChallenge)
      }

      /* 2. Готовим данные для фиксированного шаблона */
      const theme = themes[config.get<string>('application.theme')]
      const html  = pug.renderFile(
        path.join(__dirname, 'views/userProfile.pug'),
        {
          username,
          emailHash: security.hash(user.email),
          title:     config.get<string>('application.name'),
          favicon:   utils.extractFilename(config.get('application.favicon')),
          theme,
          profileImage: user.profileImage
        }
      )

      res.set('Content-Security-Policy',
              `img-src 'self' ${user.profileImage}; script-src 'self'`)
      res.send(html)

    } catch (err) {
      next(err)
    }
  }
}
