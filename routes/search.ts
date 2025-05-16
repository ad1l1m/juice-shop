/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as models from '../models/index'
import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import { challenges } from '../data/datacache'
import { JSDOM } from 'jsdom'
import createDOMPurify from 'dompurify'
import { Op, QueryTypes } from 'sequelize'

import * as utils from '../lib/utils'
const challengeUtils = require('../lib/challengeUtils')
// console.log('hello from search file')
class ErrorWithParent extends Error {
  parent: Error | undefined
}
const window = new JSDOM('').window
const DOMPurify = createDOMPurify(window)

// vuln-code-snippet start unionSqlInjectionChallenge dbSchemaChallenge
module.exports = function searchProducts () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      /* 1. Строка поиска, максимум 200 симв. */
      const criteria = String(req.query.q ?? '').slice(0, 200)

      /* 2. Параметризованный raw-query */
      const [products] = await models.sequelize.query(
        `SELECT *
           FROM Products
          WHERE ((name ILIKE :search OR description ILIKE :search)
             AND deletedAt IS NULL)
          ORDER BY name`,
        {
          replacements: { search: `%${criteria}%` },
          type: QueryTypes.SELECT
        }
      )

      /* 3. Оставляем логику челленджей (если нужна) */
      // const dataString = JSON.stringify(products) ...
      // challengeUtils.solveIf(...)

      /* 4. XSS-гигиена + локализация */
      for (const p of products as any[]) {
        p.name        = req.__(DOMPurify.sanitize(p.name))
        p.description = req.__(DOMPurify.sanitize(p.description))
      }

      res.json(utils.queryResultToJson(products))
    } catch (err) {
      /* Перехватываем ошибку SQL/Sequelize */
      next(err)
    }
  }
}

// vuln-code-snippet end unionSqlInjectionChallenge dbSchemaChallenge
