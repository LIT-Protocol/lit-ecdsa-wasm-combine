import logo from './logo.svg';
import './App.css';
import * as  wasm  from "ecdsa_wasm"
function App() {

  function combine_local_shares()
  {
    // these are return values from the nodes; the shares are from each node, and the R_x & R_y value come from ANY 1 node.
    let shares = [  '4e52aeaed3e2e07977e2d0271b0ba4d8ecaa92aad7574496c5c51aa99a1fd1a1', 
                    '4f300a5d03a85c88bc7d85d5b29b3cd608c1fa1146c41d170f65e750f9ea0264',
                    '95b1b520b25addae748e4f1cbf2c79afcef578da3285c8de71df35ba77d9930d',
                    'c323d0f7f0626e62175539607a4205695dad2ce9362398390808a64acfc92c1f',
                    '49263cfa45c1a1fd9e57e0e9a5afa7435c588e37a9c811809aa7feccf08a21a9',
                    'ebd46fde3c122047f883efca7d5557e18b0f99543a8e4e1f88e69771b53a2648',
                    '74e96f26cbc17cacee056abf4d822f76d8ad0829f6a230d8ddc239e4e1a1eef5',
                    '87d1c86bdf1c82e6d887da3b10b26d51d33693ede49f4d0391d74a2266eb1e94',
                    'aff1748ee300f71d07acd1a488a4af55ea6b5abcdd7e4b43dcd42536f3e3e7c9',
                    '1b7b48af435ad3a8ee722795bc2aba16a7e92fe3a882e47664d1beb644b88de7' ];

    let shares_vec = JSON.stringify(shares);

    let R_x = '63a62e7c00f34a9de2fb55c99e672bb347b23b75991f4217dfbe31a09b627b22';
    let R_y = '816b4d34f48365ae5df7e965d9c0292531893aa40493bc5c327e6ee39512ef31';

    
  
    wasm.default().then(()=> { 
          
        let result = wasm.combine_signature(R_x, R_y, shares_vec);
        window.alert(result); 
    
      }      
    );
  }

  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        <p>
          Edit <code>src/App.js</code> and save to reload.
        </p>
        <a
          className="App-link"
          href="https://reactjs.org"
          target="_blank"
          rel="noopener noreferrer"
        >
          Learn React
        </a>

                <button onClick={combine_local_shares} >Test Combining Shares</button>

      </header>
    </div>
  );
}

export default App;
