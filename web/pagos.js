
window.ultimaTransaccion = "";

function pagos(direccion,red, dinero, concepto) {
  // A quién vas a enviar, cuánto y en qué red '0xc17a1EA090987F355312F24c28DFfa370f2f9cDc'
  const yourAddress = direccion; //'0xc17a1EA090987F355312F24c28DFfa370f2f9cDc'
  const value = dinero; //'0x5873500000000' // un ether tiene 18 decimales, aquí en hex. 0x5873500000000
  const desiredNetwork = red || '80001'; // '80001' es el ID de la red de prueba de Polygon (Mumbai). // '1' es el ID de la red principal de Ethereum.


  // Detectar si el navegador actual es compatible con Ethereum
  // y manejar el caso en que no lo sea:
  if (typeof window.ethereum === 'undefined') {
    alert('Parece que necesitas un navegador Dapp para comenzar.');
    alert('¡Considera instalar MetaMask!');
  } else {
    // En caso de que el usuario tenga MetaMask instalado, puedes pedirles fácilmente
    // que inicien sesión y revelen sus cuentas:
    ethereum
      .request({ method: 'eth_requestAccounts' })
      // Recuerda manejar el caso en que rechacen la solicitud:
      .catch(function (reason) {
        if (reason === 'User rejected provider access') {
          // ¡El usuario no quiso iniciar sesión!
        } else {
          // Esto no debería suceder, así que podrías querer registrar esto...
          alert('Hubo un problema al iniciar sesión.');
        }
      })
      // En caso de que aprueben la solicitud de inicio de sesión, recibirás sus cuentas:
      .then(function (accounts) {
        // También debes verificar que el usuario esté en la red correcta:
        if (ethereum.networkVersion !== desiredNetwork) {
          alert(
            'Esta aplicación requiere la red principal, por favor cámbiala en tu interfaz de MetaMask.'
          );

          // Planeamos proporcionar una API para hacer esta solicitud en el futuro cercano.
          // https://github.com/MetaMask/metamask-extension/issues/3663
        }

        // Una vez que tengas una referencia a las cuentas del usuario,
        // puedes sugerir transacciones y firmas:
        const account = accounts[0];
        sendEtherFrom(account, function (err, transaction) {
          if (err) {
            return alert('Lo siento, no pudiste contribuir.');
          }

          // En lugar de alerta, asignar la transacción a la variable global
          window.ultimaTransaccion = transaction.hash;

          new QRCode(document.getElementById('qrcode'), 'datos: ' + window.ultimaTransaccion);

          alert('Pago confirmado. Transacción: ' + transaction.hash);

          //Activa_Pantalla(3)

        });
      });
  }

  function sendEtherFrom(account, callback) {
    // Vamos a usar la API de nivel más bajo aquí, con ejemplos más simples a continuación
    const method = 'eth_sendTransaction';
    const params = [
      {
        from: account,
        to: yourAddress,
        value: value,
        concepto: concepto,
      },
    ];

    // Métodos que requieren autorización del usuario como este, provocarán una interacción del usuario.
    // Otros métodos (como leer desde la cadena de bloques) pueden no hacerlo.
    ethereum
      .request({ method, params })
      .then((txHash) => {
        // Puedes verificar la cadena de bloques para ver cuándo se ha minado esta transacción:
        pollForCompletion(txHash, callback);
      })
      .catch((error) => {
        if (error.code === 4001) {
          // 4001: Usuario rechazó la solicitud
          return alert('No podemos tomar tu dinero sin tu permiso.');
        }
        alert(error.message);
      });
  }

  function pollForCompletion(txHash, callback) {
    let calledBack = false;

    // Los bloques normales de Ethereum son aproximadamente cada 15 segundos.
    // Aquí haremos una encuesta cada 2 segundos.
    const checkInterval = setInterval(function () {
      ethereum
        .request({
          method: 'eth_getTransactionByHash',
          params: [txHash],
        })
        .then((transaction) => {
          if (calledBack || !transaction || transaction.blockNumber === null) {
            // Ya hemos visto la transacción minada,
            // o no se devolvió ninguna transacción, indicando que
            // aún no se ha minado.
            return;
          }

          // La transacción ha sido minada.
          clearInterval(checkInterval);
          calledBack = true;
          callback(null, transaction);
        })
        .catch((error) => {
          if (calledBack) {
            return;
          }

          // Ocurrió algún error desconocido.
          callback(error);
        });
    }, 2000);
  }
  // fin
}
