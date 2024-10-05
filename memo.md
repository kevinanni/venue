## 虚拟环境
python -m venv appenv
appenv\Scripts\activate

## 提示词
### 框架
请生成一个简单的Streamlit代码框架，要求：
1. 有sidebar，两个页面，分别为：预约场地，系统设置
2. 两个页面分别写函数
3. 使用中文注释

### 读取config
显示my_token, my_utc, my_uuid, my_sign并允许编辑

### 填写sub_data
根据如下sub_data的结构，设计组件填写，要求：
1. venue用下拉框，显示值为"乒羽中心"，实际值为"CG8"
2. phone用输入框，默认值为18012346282
3. area用下拉框，显示值和实际值为 "羽毛球2号": "CD82", "羽毛球3号": "CD83", "羽毛球4号": "CD84","羽毛球5号": "CD85", "羽毛球7号": "CD86", "羽毛球8号": "CD87","羽毛球9号": "CD88", "羽毛球10号": "CD89",
4. date用日期选择框
5. time用下拉框，值为："12:00-13:00","18:00-19:00","19:00-20:00","20:00-21:00","21:00-22:00"


### 登录
为系统增加一个登录页面，要求：
1. 输入用户名和密码
2. 与config.ini中[Login]下的user和password比对
3. 完全符合进入主页面，否则保持登录页面



## 抓包
### 获取信息
POST /venue/venueAppointmentInfo HTTP/1.1
token: 18370c09-b7c6-4d5a-b345-a69ecc91a7d9
isApp: app
deviceId: 7811727319790848
deviceName: vivo(V2046A)
version: 3.4.1
platform: android
uuid: 7811727319790848
utc: 1728092841
sign: a507da5fbda4ae9283d6dd924deedddc
Content-Type: application/json; charset=utf-8
Content-Length: 217
Host: 210.45.246.53:8080
Connection: Keep-Alive
Accept-Encoding: gzip
User-Agent: okhttp/3.12.0

{"cipherKey":"BJpji6qutg8SoRMF33EiXiph11KeEVnspV1pqXkerSJVHRvZ1eWaKGRjXJrhNtJ/Yfk23RsMhRRJMfxf6cBe9IxXrk8nWJYcHo6bjyYRna18kFYiqIgtuuwxchIQrfBslF0S9kI3FVHOyG/kiTu/BZIdWm+QrgJmlg==","content":"D9on0Sz8K6GWGENzEBuPHg=="}

