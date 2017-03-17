/*
function http(method, url, data) {
  return new Promise((resolve, reject) => {
    let request = new XMLHttpRequest();
    request.open(method, url);
    request.onload = () => {
      if (request.status == 200) {
        resolve(request.response);
      } else {
        reject(Error(request.statusText));
      }
    };
    request.onerror = () => {
      reject(Error('Network Error'));
    };
    request.setRequestHeader("Content-Type", "application/json");
    request.responseType = 'json';
    request.send();
  });
  }*/

const http = (url, options = {}) => {
  const {method = 'GET', data = null} = options;
  const request = new XMLHttpRequest();

  return new Promise((resolve, reject) => {
    request.onload = event => {
      const response = event.target.response;

      if (event.target.status === 200 || event.target.status === 204) {
        resolve(response);
      } else {
        reject(response);
      }
    };
    request.onerror = reject;
    request.open(method, url, true);
    request.setRequestHeader("Content-Type", "application/json");
    request.responseType = 'json';
    request.send(data ? JSON.stringify(data) : data);
  });
}

export default http;
