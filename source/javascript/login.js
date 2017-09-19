import qrImage from 'qr-image';
import http from './http.js';

const id_service_url = "https://toshi-id-service.herokuapp.com";

// TODO docs on how to use as image
const getQRDataURI = (data) => {
    let pngBuffer = qrImage.imageSync(data, {type: 'png', size: 6});
  return 'data:image/png;charset=utf-8;base64, ' + pngBuffer.toString('base64');
};

function updateQRCode() {
  let qrimage = document.getElementById('qrcode');
  let datael = document.getElementById('data');
  let array = new Uint8Array(8);
  window.crypto.getRandomValues(array);
  let token = '';
  for (var i = 0; i < array.length; i++) {
    let h = array[i].toString(16);
    if (h.length == 1) {
      token += '0' + h;
    } else {
      token += h;
    }
  }
  qrimage.src = getQRDataURI("web-signin:" + token);
  return token;
}

function run() {
  let token = updateQRCode();
  http(id_service_url + '/v1/login/' + token).then((data) => {
    return http('/login', {method: 'POST', data: data}).then((data) => {
      let path = new URLSearchParams(document.location.search).get('redirect');
      if (path == null || path == '') {
        path = '/';
      }
      document.location.href = path;
    });
  }).catch((error) => {
    console.log(error);
    run();
  });
}

run();
