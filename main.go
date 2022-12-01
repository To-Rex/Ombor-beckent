package main

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/trycourier/courier-go/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"golang.org/x/crypto/bcrypt"
)

const uri = "mongodb+srv://root:0000@cluster0.kncismv.mongodb.net/?retryWrites=true&w=majority"

type User struct {
	Name         string `json:"name"`
	Surname      string `json:"surname"`
	Phone        string `json:"phone"`
	Country      string `json:"country"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	RegisterDate string `json:"register_date"`
	Verified     bool   `json:"verified"`
	Blocked      bool   `json:"blocked"`
	Token        string `json:"token"`
	UserId       string `json:"user_id"`
	UserStatus   string `json:"user_status"`
	UserRole     string `json:"user_role"`
	UserAvatar   string `json:"user_avatar"`
}

type ProductCategory struct {
	CategoryName string `json:"category_name"`
	CategoryId   string `json:"category_id"`
	CategoryIcon string `json:"category_icon"`
}

type Product struct {
	ProductId   string `json:"product_id"`
	ProductName string `json:"product_name"`
	ProductDesc string `json:"product_desc"`
	ProductImg  string `json:"product_img"`
	ProductCatId string `json:"product_cat_id"`
	ProductPrice int64 `json:"product_price"`
	ProductStock string `json:"product_stock"`
	ProductStatus string `json:"product_status"`
	ProductDate string `json:"product_date"`
	ProductSeller string `json:"product_seller"`
	ProductNumber int64 `json:"product_number"`
}

type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Register struct {
	Name     string `json:"name"`
	Surname  string `json:"surname"`
	Years    int    `json:"years"`
	Phone    string `json:"phone"`
	Country  string `json:"country"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UpdatePassword struct {
	Email          string `json:"email"`
	Password       string `json:"password"`
	NewPassword    string `json:"new_password"`
	RepeatPassword string `json:"repeat_password"`
}

func main() {
	router := gin.Default()
	router.POST("/register", register)
	router.POST("/login", login)
	router.POST("/verifyUser", verifyUser)
	router.GET("/getAllUsers", getAllUsers)
	router.GET("/getUser", getUser)
	router.POST("/updatePassword", updatePassword)
	router.POST("/updateBlockedStatus", updateBlockedStatus)
	router.POST("/resendVerificationCode", resendVerificationCode)
	router.POST("/addProductCategory", addProductCategory)
	router.POST("/addProduct", addProduct)
	router.GET("/getAllProductCategories", getAllProductCategories)
	router.GET("/getAllProducts", getAllProducts)
	router.GET("/getProductsByCategory", getProductsByCategory)
	router.DELETE("/deleteCategory", deleteCategory)
	router.DELETE("/deleteProduct", deleteProduct)
	router.POST("/productSell", productSell)
	router.POST("/addProductSell", addProductSell)
	
	router.Run()
}

func createToken(username string) string {
	claims := jwt.MapClaims{}
	claims["authorized"] = true
	claims["email"] = username
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(os.Getenv("SECRET")))
	return tokenString
}

func passwordHash(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		fmt.Println(err)
	}
	return string(hash)
}

// generate userid random cheracter 32 length string
func generateUserId() string {
	rand.Seed(time.Now().UnixNano())
	chars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	length := 32
	b := make([]rune, length)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}


func randomCode() string {
	//random int code 6	length number
	rand.Seed(time.Now().UnixNano())
	chars := []rune("0123456789")
	length := 6
	b := make([]rune, length)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func sendMailSimple(email string, code string) {
	client := courier.CreateClient("pk_prod_K10S0E6XF2MSA5MFK6E33ECTFJ9M", nil)
	requestID, err := client.SendMessage(
		context.Background(),
		courier.SendMessageRequestBody{
			Message: map[string]interface{}{
				"to": map[string]string{
					"email": email,
				},
				"template": "K4PMX20GEM4121GAFQJBH30JSSGD",
				"data": map[string]string{
					"recipientName": code,
				},
			},
		},
	)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(requestID)
	}
}

func register(c *gin.Context) {
	var register Register
	c.BindJSON(&register)
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, nx := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	if nx != nil {
		fmt.Println(nx)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	collection := client.Database("Partners").Collection("users")
	var user User
	err = collection.FindOne(ctx, bson.M{"email": register.Email}).Decode(&user)
	if err != nil {
		fmt.Println(err)
	}
	if user.Email == register.Email {
		c.JSON(http.StatusConflict, gin.H{"status": http.StatusConflict, "message": "User already exists"})
		return
	}
	hash := passwordHash(register.Password)
	userId := generateUserId()
	user = User{
		Name:         register.Name,
		Surname:      register.Surname,
		Phone:        register.Phone,
		Country:      register.Country,
		Email:        register.Email,
		Password:     hash,
		RegisterDate: time.Now().Format("2003-03-31 15:04:05"),
		Verified:     false,
		Blocked:      false,
		Token:        createToken(register.Email),
		UserId:       userId,
		UserStatus:   "user",
		UserRole:     "user",
		UserAvatar:   "",
	}
	_, err = collection.InsertOne(ctx, user)
	if err != nil {
		fmt.Println(err)
	}
	//return user token, user id, user role, user status
	code := randomCode()
	sendMailSimple(register.Email, code)
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "User created", "token": user.Token, "user_id": user.UserId, "user_role": user.UserRole, "user_status": user.UserStatus, "verify_code": code})
}

func login(c *gin.Context) {
	var login Login
	c.BindJSON(&login)
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, nx := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	if nx != nil {
		fmt.Println(nx)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	collection := client.Database("Partners").Collection("users")
	var user User
	err = collection.FindOne(ctx, bson.M{"email": login.Email}).Decode(&user)
	fmt.Println(user)
	if err != nil {
		fmt.Println(err)
	}
	if user.Email == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "User not found"})
		return
	}
	if !user.Verified {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User not verified"})
		return
	}
	if user.Blocked {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User blocked"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(login.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized, "message": "Invalid credentials"})
		return
	}
	//return user token, user id, user role, user status
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "User logged in", "token": user.Token, "user_id": user.UserId, "user_role": user.UserRole, "user_status": user.UserStatus})
}

func verifyUser(c *gin.Context) {
	var user User
	c.BindJSON(&user)
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, nx := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	if nx != nil {
		fmt.Println(nx)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	collection := client.Database("Partners").Collection("users")
	filter := bson.M{"email": user.Email}

	var result User
	err = collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		fmt.Println(err)
	}
	if result.Email == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "User not found"})
		return
	}
	if result.Verified {
		c.JSON(http.StatusConflict, gin.H{"status": http.StatusConflict, "message": "User already verified"})
		return
	}
	if result.Blocked {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User blocked"})
		return
	}
	if !result.Verified {
		update := bson.M{"$set": bson.M{"verified": true}}
		_, err = collection.UpdateOne(ctx, filter, update)
		if err != nil {
			fmt.Println(err)
		}
	}
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "User verified"})
}

func resendVerificationCode(c *gin.Context) {
	var user User
	c.BindJSON(&user)
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, nx := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	if nx != nil {
		fmt.Println(nx)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	collection := client.Database("Partners").Collection("users")
	filter := bson.M{"email": user.Email}

	var result User
	err = collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		fmt.Println(err)
	}
	if result.Email == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "User not found"})
		return
	}
	if result.Verified {
		c.JSON(http.StatusConflict, gin.H{"status": http.StatusConflict, "message": "User already verified"})
		return
	}
	if result.Blocked {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User blocked"})
		return
	}
	if !result.Verified {
		code := randomCode()
		sendMailSimple(result.Email, code)
		c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Verification code sent", "verify_code": code})
		return
	} else {
		c.JSON(http.StatusConflict, gin.H{"status": http.StatusConflict, "message": "User already verified"})
		return
	}
}

func getAllUsers(c *gin.Context) {
	var users []User
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, nx := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	if nx != nil {
		fmt.Println(nx)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	collection := client.Database("Partners").Collection("users")
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		fmt.Println(err)
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var user User
		cursor.Decode(&user)
		users = append(users, user)
	}
	if err := cursor.Err(); err != nil {
		fmt.Println(err)
	}
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Users found", "users": users})
}

func getUser(c *gin.Context) {
	var user User
	c.BindJSON(&user)
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, nx := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	if nx != nil {
		fmt.Println(nx)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	collection := client.Database("Partners").Collection("users")
	var result User
	err = collection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&result)
	if err != nil {
		fmt.Println(err)
	}
	if result.Email == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "User not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "User found", "user": result})
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	fmt.Println(err)

	return err == nil
}

func updatePassword(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	token = token[7:]
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, nx := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	if nx != nil {
		fmt.Println(nx)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	collection := client.Database("Partners").Collection("users")
	var updatePassword UpdatePassword
	c.BindJSON(&updatePassword)
	filter := bson.M{"email": claims["email"]}
	var result User
	err = collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		fmt.Println(err)
	}
	if result.Email == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "User not found"})
		return
	}
	if result.Blocked {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User blocked"})
		return
	}
	if !result.Verified {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User not verified"})
		return
	}

	if updatePassword.NewPassword != updatePassword.RepeatPassword {
		c.JSON(http.StatusConflict, gin.H{"status": http.StatusConflict, "message": "Passwords don't match"})
		return
	}

	if !CheckPasswordHash(updatePassword.Password, result.Password) {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "password is incorrect"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(updatePassword.NewPassword), 10)
	if err != nil {
		fmt.Println(err)
	}
	update := bson.M{"$set": bson.M{"password": string(hash)}}
	_, err = collection.UpdateOne(ctx, filter, update)
	if err != nil {
		fmt.Println(err)
	}
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Password updated"})
}

func updateBlockedStatus(c *gin.Context) {
	//no bearer token
	var user User
	c.BindJSON(&user)
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, nx := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	if nx != nil {
		fmt.Println(nx)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	collection := client.Database("Partners").Collection("users")
	filter := bson.M{"email": user.Email}
	var result User
	err = collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		fmt.Println(err)
	}
	if result.Email == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "User not found"})
		return
	}
	if result.UserRole == "creator" {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User is creator"})
		return
	}
	update := bson.M{"$set": bson.M{"blocked": user.Blocked}}
	_, err = collection.UpdateOne(ctx, filter, update)
	if err != nil {
		fmt.Println(err)
	}
	// if user blocked true return user blocked status true else return false
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "User blocked status updated", "blocked": user.Blocked})
}

func addProductCategory(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	token = token[7:]
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, nx := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	if nx != nil {
		fmt.Println(nx)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	collection := client.Database("Partners").Collection("users")
	var productCategory ProductCategory
	c.BindJSON(&productCategory)
	filter := bson.M{"email": claims["email"]}
	var result User
	err = collection.FindOne(ctx, filter ).Decode(&result)
	if err != nil {
		fmt.Println(err)
	}
	if result.Email == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "User not found"})
		return
	}
	if result.Blocked {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User blocked"})
		return
	}
	if !result.Verified {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User not verified"})
		return
	}
	if result.UserRole != "creator" {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User is not creator"})
		return
	}
	//categoryid generateid() function call here
	productCategory.CategoryId = generateUserId()

	collection = client.Database("Partners").Collection("Categories")
	_, err = collection.InsertOne(ctx, productCategory)
	if err != nil {
		fmt.Println(err)
	}
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Product category added"})
}

func addProduct(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	token = token[7:]
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, nx := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	if nx != nil {
		fmt.Println(nx)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	collection := client.Database("Partners").Collection("users")
	var product Product
	c.BindJSON(&product)
	filter := bson.M{"email": claims["email"]}
	var result User
	err = collection.FindOne(ctx, filter ).Decode(&result)
	if err != nil {
		fmt.Println(err)
	}
	if result.Email == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "User not found"})
		return
	}
	if result.Blocked {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User blocked"})
		return
	}
	if !result.Verified {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User not verified"})
		return
	}
	if result.UserRole != "creator" {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User is not creator"})
		return
	}

	product.ProductId = generateUserId()
	product.ProductDate = time.Now().Format("2006-01-02 15:04:05")
	product.ProductSeller = result.UserId

	collection = client.Database("Partners").Collection("Products")
	_, err = collection.InsertOne(ctx, product)
	if err != nil {
		fmt.Println(err)
	}
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Product added"})
}

func getAllProductCategories(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	token = token[7:]
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	} )
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, nx := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	if nx != nil {
		fmt.Println(nx)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	collection := client.Database("Partners").Collection("users")
	filter := bson.M{"email": claims["email"]}
	var result User
	err = collection.FindOne(ctx, filter ).Decode(&result)
	if err != nil {
		fmt.Println(err)
	}
	if result.Email == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "User not found"})
		return
	}
	if result.Blocked {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User blocked"})
		return
	}
	if !result.Verified {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User not verified"})
		return
	}
	if result.UserRole != "creator" {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User is not creator"})
		return
	}
	collection = client.Database("Partners").Collection("Categories")
	var productCategories []ProductCategory
	cur, err := collection.Find(ctx, bson.M{})
	if err != nil {
		fmt.Println(err)
	}
	for cur.Next(ctx) {
		var productCategory ProductCategory
		err := cur.Decode(&productCategory)
		if err != nil {
			fmt.Println(err)
		}
		productCategories = append(productCategories, productCategory)
	}
	if err := cur.Err(); err != nil {
		fmt.Println(err)
	}
	cur.Close(ctx)
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Product categories", "data": productCategories})
}

func getAllProducts(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	token = token[7:]
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	} )
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, nx := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	if nx != nil {
		fmt.Println(nx)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	collection := client.Database("Partners").Collection("users")
	filter := bson.M{"email": claims["email"]}
	var result User
	err = collection.FindOne(ctx, filter ).Decode(&result)
	if err != nil {
		fmt.Println(err)
	}
	if result.Email == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "User not found"})
		return
	}
	if result.Blocked {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User blocked"})
		return
	}
	if !result.Verified {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User not verified"})
		return
	}

	collection = client.Database("Partners").Collection("Products")
	var products []Product
	cur, err := collection.Find(ctx, bson.M{})
	if err != nil {
		fmt.Println(err)
	}
	for cur.Next(ctx) {
		var product Product
		err := cur.Decode(&product)
		if err != nil {
			fmt.Println(err)
		}
		products = append(products, product)
	}
	if err := cur.Err(); err != nil {
		fmt.Println(err)
	}
	cur.Close(ctx)
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Products", "data": products})
}

//if Products in productcatid == query param productcatid, return products in that category	
func getProductsByCategory(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	token = token[7:]
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	} )
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, nx := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	if nx != nil {
		fmt.Println(nx)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	collection := client.Database("Partners").Collection("users")
	filter := bson.M{"email": claims["email"]}
	var result User
	err = collection.FindOne(ctx, filter ).Decode(&result)
	if err != nil {
		fmt.Println(err)
	}
	if result.Email == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "User not found"})
		return
	}
	if result.Blocked {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User blocked"})
		return
	}
	if !result.Verified {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User not verified"})
		return
	}
	collection = client.Database("Partners").Collection("Products")
	var products []Product
	cur, err := collection.Find(ctx, bson.M{})
	if err != nil {
		fmt.Println(err)
	}
	for cur.Next(ctx) {
		var product Product
		err := cur.Decode(&product)
		if err != nil {
			fmt.Println(err)
		}
		products = append(products, product)
	}
	if err := cur.Err(); err != nil {
		fmt.Println(err)
	}
	cur.Close(ctx)
	var productsByCategory []Product
	for _, product := range products {
		if product.ProductCatId == c.Query("categoryId") {
			productsByCategory = append(productsByCategory, product)
		}
	}
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "data": productsByCategory})
}

func deleteCategory(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	token = token[7:]
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	} )
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, nx := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	if nx != nil {
		fmt.Println(nx)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	collection := client.Database("Partners").Collection("users")
	filter := bson.M{"email": claims["email"]}
	var result User
	err = collection.FindOne(ctx, filter ).Decode(&result)
	if err != nil {
		fmt.Println(err)
	}
	if result.Email == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "User not found"})
		return
	}
	if result.Blocked {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User blocked"})
		return
	}
	if !result.Verified {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User not verified"})
		return
	}
	var category ProductCategory
	err = c.BindJSON(&category)
	if err != nil {
		fmt.Println(err)
	}
	collection = client.Database("Partners").Collection("Categories")
	filter = bson.M{"categoryid": c.Query("categoryId")}
	_, err = collection.DeleteOne(ctx, filter )
	if err != nil {
		fmt.Println(err)
	}

	var products []Product
	collection = client.Database("Partners").Collection("Products")
	cur, err := collection.Find(ctx, bson.M{})
	if err != nil {
		fmt.Println(err)
	}
	for cur.Next(ctx) {
		var product Product
		err := cur.Decode(&product)
		if err != nil {
			fmt.Println(err)
		}
		products = append(products, product)
	}
	if err := cur.Err(); err != nil {
		fmt.Println(err)
	}
	cur.Close(ctx)
	for _, product := range products {
		if product.ProductCatId == c.Query("categoryId") {
			filter = bson.M{"productid": product.ProductId}
			_, err = collection.DeleteOne(ctx, filter )
			if err != nil {
				fmt.Println(err)
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Category deleted successfully"})
}

func deleteProduct(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	token = token[7:]
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	} )
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, nx := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	if nx != nil {
		fmt.Println(nx)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	collection := client.Database("Partners").Collection("users")
	filter := bson.M{"email": claims["email"]}
	var result User
	err = collection.FindOne(ctx, filter ).Decode(&result)
	if err != nil {
		fmt.Println(err)
	}
	if result.Email == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "User not found"})
		return
	}
	if result.Blocked {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User blocked"})
		return
	}
	if !result.Verified {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User not verified"})
		return
	}
	collection = client.Database("Partners").Collection("Products")
	filter = bson.M{"productid": c.Query("productId")}
	_, err = collection.DeleteOne(ctx, filter )
	if err != nil {
		fmt.Println(err)
	}
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Product deleted successfully"})
}

func productSell(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	token = token[7:]
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, nx := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	if nx != nil {
		fmt.Println(nx)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	collection := client.Database("Partners").Collection("users")
	filter := bson.M{"email": claims["email"]}
	var result User
	err = collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		fmt.Println(err)
	}
	if result.Email == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "User not found"})
		return
	}
	if result.Blocked {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User blocked"})
		return
	}
	if !result.Verified {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User not verified"})
		return
	}
	collection = client.Database("Partners").Collection("Products")
	filter = bson.M{"productid": c.Query("productId")}
	number, err := strconv.Atoi(c.Query("number"))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(filter)
	var product Product
	err = collection.FindOne(ctx, filter ).Decode(&product)
	fmt.Println(product)
	if err != nil {
		fmt.Println(err)
	}
	if product.ProductId == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "Product not found"})
		return
	}
	if product.ProductSeller != result.UserId {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User not authorized"})
		return
	}
	if int(product.ProductNumber) < number { 
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "Not enough products"})
		return
	}
	product.ProductNumber = product.ProductNumber - int64(number)
	update := bson.M{"$set": bson.M{"productnumber": product.ProductNumber}}
	_, err = collection.UpdateOne(ctx, filter , update)
	if err != nil {
		fmt.Println(err)
	}
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Product sold successfully"})
}

func addProductSell(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	token = token[7:]
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, nx := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	if nx != nil {
		fmt.Println(nx)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	collection := client.Database("Partners").Collection("users")
	filter := bson.M{"email": claims["email"]}
	var result User
	err = collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		fmt.Println(err)
	}
	if result.Email == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "User not found"})
		return
	}
	if result.Blocked {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User blocked"})
		return
	}
	if !result.Verified {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User not verified"})
		return
	}
	collection = client.Database("Partners").Collection("Products")
	filter = bson.M{"productid": c.Query("productId")}
	number, err := strconv.Atoi(c.Query("number"))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(filter)
	var product Product
	err = collection.FindOne(ctx, filter ).Decode(&product)
	fmt.Println(product)
	if err != nil {
		fmt.Println(err)
	}
	if product.ProductId == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "Product not found"})
		return
	}
	if product.ProductSeller != result.UserId {
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "User not authorized"})
		return
	}
	if 0 > number { 
		c.JSON(http.StatusForbidden, gin.H{"status": http.StatusForbidden, "message": "Not enough products"})
		return
	}
	
	product.ProductNumber = product.ProductNumber + int64(number)
	update := bson.M{"$set": bson.M{"productnumber": product.ProductNumber}}
	_, err = collection.UpdateOne(ctx, filter , update)
	if err != nil {
		fmt.Println(err)
	}
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "Product added successfully"})
}

