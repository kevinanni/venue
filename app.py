import streamlit as st

# 设置页面标题
st.title("欢迎使用预约系统")

# 创建侧边栏
st.sidebar.title("导航")
page = st.sidebar.radio("选择页面", ("预约场地", "系统设置"))

# 根据选择的页面显示内容
if page == "预约场地":
    st.header("预约场地")
    st.write("在这里您可以预约场地。")
    # 这里可以添加更多的预约功能代码

elif page == "系统设置":
    st.header("系统设置")
    st.write("在这里您可以进行系统设置。")
    # 这里可以添加更多的系统设置代码
