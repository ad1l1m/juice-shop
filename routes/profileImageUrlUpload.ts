/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'
import logger from '../lib/logger'
import stream from 'stream'

import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import { promisify } from 'util'
const security = require('../lib/insecurity')
const request = require('request')
const ssrfFilter = require('ssrf-req-filter');
const axios = require('axios').default;
const pipeline = promisify(stream.pipeline)
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
        try {
          /* ─── 1. HTTP-запрос ─── */
          const response = await axios.get(url, {
            responseType: 'stream',      // отдаём поток
            timeout: 3000,               // 3 с
            maxRedirects: 3              // как у старого request
          })

          /* ─── 2. Проверяем код ответа ─── */
          if (response.status !== 200) {
            await UserModel.update(
              { profileImage: url },
              { where: { id: loggedInUser.data.id } }
            )
            return
          }

          /* ─── 3. Определяем расширение ─── */
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif']
                      .find(e => url.toLowerCase().endsWith('.' + e)) ?? 'jpg'

          const destPath = `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`

          /* ─── 4. Сохраняем на диск ─── */
          await pipeline(response.data, fs.createWriteStream(destPath))

          /* ─── 5. Обновляем запись пользователя ─── */
          await UserModel.update(
            { profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` },
            { where: { id: loggedInUser.data.id } }
          )

        } catch (err) {
          /* ─── 6. Обработка ошибок ─── */
          logger.warn(
            `Error retrieving user profile image: ${utils.getErrorMessage(err)}; storing link only`
          )
          await UserModel.update(
            { profileImage: url },
            { where: { id: loggedInUser.data.id } }
          )
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
