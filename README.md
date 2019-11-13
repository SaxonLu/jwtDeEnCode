# jwtDeEnCode
Easy Sample For Goalng Encode Decode Jwt Token

## 使用方式

### Encode Request

Request Url => localhost:8090/login

Body內填入 
```json
{
	"username":"someone",
	"password":"qwer!1234@aaa123"
}
```
送出後會取得Encode後的Token

### Decode Request

Request Url => localhost:8090/resource
>Header 
>>Key : Authorization

>>Value : Jwt雜湊後的Token

送出後會取得Decode後的Json資料
