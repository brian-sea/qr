function logoutUser(evt){
    evt.preventDefault();

    let path = window.location.pathname.lastIndexOf('/');
    if( window.location.pathname.slice(path) === '/admin' ) {
       path = window.location.pathname.slice(0,path);
       path = path.lastIndexOf('/');
    }
    path = window.location.pathname.slice(0, path);
    let URL = path + '/logout';
    
    let element = document.activeElement;
    let identity = element.value;
    let postData = {
        identity
    }
    
    fetch(URL, {
        method: 'POST', 
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(postData)
    }).then( function(response) {
        response.json().then(function(data) {
            if( data.status === true ){
                element.parentNode.parentNode.removeChild(element.parentNode);
                
                // Only fire the submit if the password is visible
                let adminPassword = document.querySelector('form#formPassword');
                if( window.getComputedStyle(adminPassword, null).display !== 'none' ) {
                    document.querySelector('form#formPassword').requestSubmit();
                }
            }
        }).catch(function(err) {
            console.log('Error: ', err.toString());
        })
    }).catch(function(err){
        console.log( 'Error: ', err.toString());
    })        
}
