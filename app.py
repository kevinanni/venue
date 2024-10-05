import configparser
import streamlit as st

from venue import my_token, my_utc, my_uuid, my_sign, save_config, venueHomPage, submitAppointment

# # 设置页面标题
# st.title("欢迎使用预约系统")

# 创建侧边栏
st.sidebar.title("导航")
page = None
# 登录页面
if 'logged_in' not in st.session_state or not st.session_state.logged_in:
    username = st.sidebar.text_input("用户名")
    password = st.sidebar.text_input("密码", type="password")
    if st.sidebar.button("登录"):
        config = configparser.ConfigParser()
        config.read('config.ini')
        if username == config['Login']['user'] and password == config['Login'][
                'password']:
            st.session_state.logged_in = True
            st.sidebar.success("登录成功！")
            st.rerun()
        else:
            st.sidebar.error("用户名或密码错误，请重试。")
else:
    page = st.sidebar.radio("选择页面", ("预约场地", "系统设置"))


# 定义预约场地页面的函数
def appointment_page():
    st.header("预约场地")
    if st.button("查看场地"):
        data = venueHomPage()
        st.write(data)
    st.subheader("预约信息")
    # 创建一个字典来存储预约信息
    sub_data = {
        "venueNumber":
        "CG8",  # 选择的场地
        "phone":
        st.text_input("电话", value="18012346282"),  # 输入框，默认值为18012346282
        "areaNumber":
        st.selectbox(
            "选择区域",
            options=[
                "CD82", "CD83", "CD84", "CD85", "CD86", "CD87", "CD88", "CD89"
            ],  # 下拉框选择区域
            format_func=lambda x: {
                "CD82": "羽毛球2号",
                "CD83": "羽毛球3号",
                "CD84": "羽毛球4号",
                "CD85": "羽毛球5号",
                "CD86": "羽毛球7号",
                "CD87": "羽毛球8号",
                "CD88": "羽毛球9号",
                "CD89": "羽毛球10号"
            }[x]),
        "appointmentDate":
        st.date_input("选择日期").strftime("%Y-%m-%d"),  # 日期选择框，转换为字符串yyyy-mm-dd
        "selVenueFieldTime":
        st.selectbox("选择时间",
                     options=[
                         "08:00-09:00", "09:00-10:00", "10:00-11:00",
                         "11:00-12:00", "12:00-13:00", "13:00-14:00",
                         "14:00-15:00", "15:00-16:00", "16:00-17:00",
                         "17:00-18:00", "18:00-19:00", "19:00-20:00",
                         "20:00-21:00", "21:00-22:00"
                     ])  # 下拉框选择时间
    }
    if st.button("预约"):
        re = submitAppointment(sub_data)
        st.write(re)


# 定义系统设置页面的函数
def settings_page():
    st.header("系统设置")

    global my_token, my_utc, my_uuid, my_sign
    # 显示和编辑 my_token
    my_token = st.text_input("Token", value=my_token)

    # 显示和编辑 my_utc
    my_utc = st.text_input("UTC", value=my_utc)

    # 显示和编辑 my_uuid
    my_uuid = st.text_input("UUID", value=my_uuid)

    # 显示和编辑 my_sign
    my_sign = st.text_input("Sign", value=my_sign)

    # 可以添加保存按钮
    if st.button("保存设置"):
        save_config(my_token, my_utc, my_uuid, my_sign)
        st.success("设置已保存！")


# 根据选择的页面显示内容
if page == "预约场地":
    appointment_page()
elif page == "系统设置":
    settings_page()
