/**
 * @Author: guxline zjguoxin@163.com
 * @Date: 2025/7/7 07:36:51
 * @LastEditors: guxline zjguoxin@163.com
 * @LastEditTime: 2025/7/7 07:36:51
 * Description: 示例
 * Copyright: Copyright (©) 2025 中易综服. All rights reserved.
 */
package main

import (
	"log"

	"github.com/gin-gonic/gin"
	gosjwt "github.com/zjguoxin/gos-jwt"
	"github.com/zjguoxin/gos-jwt/global"
	"github.com/zjguoxin/gos-jwt/route"
)

func main() {
	r := gin.Default()

	config := &gosjwt.Config{
		SigningKey:             []byte("yoursecretkey"), // Use a strong secret key in production
		Issuer:                 "appname",               // 发行人
		Expires:                -1,                      // 过期时间，单位小时 24小时
		GracePeriod:            0,                       // 宽限期，单位秒
		BlacklistCleanDuration: 3600,                    // 黑名单清理间隔，单位分钟
		Cache: gosjwt.CacheConfig{
			Prefix:    "gosjwt_",        // 缓存前缀
			Type:      "redis",          // redis|memory
			RedisAddr: "127.0.0.1:6379", // redis地址 type=redis时生效
			RedisPass: "",               // redis密码 type=redis时生效
			RedisDB:   11,               // redis数据库 type=redis时生效
		},
	}

	JwtHandler, err := gosjwt.NewJwtHandler(config)

	global.JwtHandler = JwtHandler

	if err != nil {
		log.Fatalf("初始化JWT处理器失败: %v", err)
	}

	r = route.Route(r)
	// 使用中间件
	// r.Use(JwtHandler.GinMiddleware())

	r.Run(":8080")
	// userID := uint(12345)
	// tokenString, err := jwtHandler.ReleaseToken(userID)
	// if err != nil {
	// 	log.Fatalf("Failed to generate token: %v", err)
	// }
	// fmt.Printf("Generated Token: %s\n", tokenString)

	// // 2. Parse and validate the token
	// token, claims, err := jwtHandler.ParseToken(tokenString)
	// if err != nil {
	// 	log.Fatalf("Failed to parse token: %v", err)
	// }

	// if !token.Valid {
	// 	log.Fatal("Invalid token")
	// }

	// fmt.Printf("Token is valid. Claims: %+v\n", claims)
	// fmt.Printf("User ID from token: %d\n", claims.UserId)

	// // 3. Verify the user ID matches
	// if claims.UserId != userID {
	// 	log.Fatal("Token user ID doesn't match expected value")
	// } else {
	// 	fmt.Println("Token user ID verification successful")
	// }
}
