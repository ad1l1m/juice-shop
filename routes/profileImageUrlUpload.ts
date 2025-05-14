/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'
import logger from '../lib/logger'

import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
const security = require('../lib/insecurity')
const request = require('request')
const ssrfFilter = require('ssrf-req-filter');

async function isSafeUrl(inputUrl: string): Promise<boolean> {
  const dns = require('dns').promises
  const net = require('net')
  const urlLib = require('url')
  try {
    const parsed = new URL(inputUrl)
    const hostname = parsed.hostname
    const { address } = await dns.lookup(hostname)
    const ip = address
    const blockedRanges = [
      /^127\./,                // loopback
      /^10\./,                 // private
      /^192\.168\./,           // private
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // private
      /^0\./,                  // "this" network
      /^169\.254\./,           // link-local
      /^::1$/,                 // IPv6 loopback
      /^fc00:/,                // IPv6 private
      /^fe80:/                 // IPv6 link-local
    ]
    return !blockedRanges.some((range) => range.test(ip))
  } catch (e) {
    return false
  }
}

module.exports = function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      const isSafe = await isSafeUrl(url)
      if (!isSafe) {
        return res.status(403).send('Blocked by SSRF protection')
      }

      if (loggedInUser) {
        const imageRequest = request
          .get(url)
          .on('error', function (err: unknown) {
            UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: url }) }).catch((error: Error) => { next(error) })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(err)}; using image link directly`)
          })
          .on('response', function (res: Response) {
            if (res.statusCode === 200) {
              const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
              console.log(loggedInUser)
              imageRequest.pipe(fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`))
              UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
            } else UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: url }) }).catch((error: Error) => { next(error) })
          })
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
