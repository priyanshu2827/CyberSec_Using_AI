import axios from "axios";

export function getApi() {
  const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
  const API = `${BACKEND_URL}/api`;
  const inst = axios.create({ baseURL: API, timeout: 30000 });
  return inst;
}