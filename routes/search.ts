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
  console.log('////////////////////')
  // console.log('hello from search file')
  return (req: Request, res: Response, next: NextFunction) => {
    // console.log('Query params:', req)
    // console.log('Response params', res)
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    // console.log('Raw q:', req.query.q)
    // console.log('Processed criteria:', criteria) 
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    // console.log(req.query.q)
    models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`) // vuln-code-snippet vuln-line unionSqlInjectionChallenge dbSchemaChallenge
      .then(([products]: any) => {
      //   for (let i = 0; i < products.length; i++) {
      //     products[i].name = req.__(DOMPurify.sanitize(products[i].name))
      //     products[i].description = req.__(DOMPurify.sanitize(products[i].description))
      // }             
        const dataString = JSON.stringify(products)
        // console.log(dataString, 'dataString')
        if (challengeUtils.notSolved(challenges.unionSqlInjectionChallenge)) { // vuln-code-snippet hide-start
          let solved = true
          UserModel.findAll().then(data => {
            const users = utils.queryResultToJson(data)
            if (users.data?.length) {
              for (let i = 0; i < users.data.length; i++) {
                solved = solved && utils.containsOrEscaped(dataString, users.data[i].email) && utils.contains(dataString, users.data[i].password)
                if (!solved) {
                  break
                }
              }
              if (solved) {
                challengeUtils.solve(challenges.unionSqlInjectionChallenge)
              }
            }
          }).catch((error: Error) => {
            next(error)
          })
        }
        if (challengeUtils.notSolved(challenges.dbSchemaChallenge)) {
          let solved = true
          void models.sequelize.query('SELECT sql FROM sqlite_master').then(([data]: any) => {
            const tableDefinitions = utils.queryResultToJson(data)
            // console.log(tableDefinitions, 'tableDefinition')
            if (tableDefinitions.data?.length) {
              for (let i = 0; i < tableDefinitions.data.length; i++) {
                if (tableDefinitions.data[i].sql) {
                  solved = solved && utils.containsOrEscaped(dataString, tableDefinitions.data[i].sql)
                  if (!solved) {
                    break
                  }
                }
              }
              if (solved) {
                challengeUtils.solve(challenges.dbSchemaChallenge)
              }
            }
          })
        } // vuln-code-snippet hide-end
        for (let i = 0; i < products.length; i++) {
          // console.log(products,'products')
          products[i].name = req.__(DOMPurify.sanitize(products[i].name));
          products[i].description = req.__(DOMPurify.sanitize(products[i].description));
          // products[i].name = req.__(products[i].name)
          // products[i].description = req.__(products[i].description)
        }
        res.json(utils.queryResultToJson(products))
        // console.log(products+'   products')
      }).catch((error: ErrorWithParent) => {
        next(error.parent)
      })
  }
}
// vuln-code-snippet end unionSqlInjectionChallenge dbSchemaChallenge
