import axios from 'axios'

const BASE_URL = 'http://localhost:3000'; // 后端服务地址

export const scanXSS = async (url: string) => {
  const res = await axios.post(`${BASE_URL}/scan/xss`, { url });
  return res.data;
};