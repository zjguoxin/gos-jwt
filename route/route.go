/**
 * @Author: guxline zjguoxin@163.com
 * @Date: 2025/7/8 04:05:39
 * @LastEditors: guxline zjguoxin@163.com
 * @LastEditTime: 2025/7/8 04:05:39
 * Description:
 * Copyright: Copyright (©) 2025 中易综服. All rights reserved.
 */
package route

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/zjguoxin/gos-jwt/global"
)

func Route(r *gin.Engine) *gin.Engine {

	v1 := r.Group("/v1")

	Auth := v1.Group("/auth")
	{
		Auth.POST("/login", func(ctx *gin.Context) {
			userIdStr := ctx.PostForm("user_id")
			userInt, _ := strconv.Atoi(userIdStr)
			userId := uint(userInt)
			token, err := global.JwtHandler.ReleaseToken(userId)
			if err != nil {
				ctx.JSON(http.StatusInternalServerError, gin.H{"code": 500, "result": "error", "data": nil, "msg": "登录失败"})
				return
			}
			ctx.JSON(http.StatusOK, gin.H{"code": 200, "result": "success", "data": token, "msg": "登录成功"})
		})
		Auth.POST("/verify", global.JwtHandler.GinMiddleware(), func(ctx *gin.Context) {
			userId, err := ctx.Get("userID")
			if !err {
				ctx.JSON(http.StatusInternalServerError, gin.H{"code": 500, "result": "error", "data": nil, "msg": "验证失败"})
				return
			}
			userID, ok := userId.(uint)
			if !ok {
				ctx.JSON(http.StatusInternalServerError, gin.H{"code": 500, "result": "error", "data": nil, "msg": "断言失败"})
				return
			}

			ctx.JSON(http.StatusOK, gin.H{"code": 200, "result": "success", "data": userID, "msg": "验证成功"})
		})
	}

	return r
}
