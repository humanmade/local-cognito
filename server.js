const { send, json } = require( 'micro' );
const {
	router,
	options,
	post,
	get,
} = require( 'micro-fork' );

const uuid = placeholder =>
	placeholder
		? ( placeholder ^ ( ( Math.random() * 16 ) >> ( placeholder / 4 ) ) ).toString( 16 )
		: ( [ 1e7 ] + -1e3 + -4e3 + -8e3 + -1e11 ).replace( /[018]/g, uuid );

const setHeaders = ( req, res, headers = {} ) => {
	res.setHeader( 'access-control-allow-origin', '*' );
	if ( req.headers['access-control-request-headers'] ) {
		res.setHeader( 'access-control-allow-headers', req.headers['access-control-request-headers'] );
	}
	res.setHeader( 'access-control-expose-headers', 'x-amzn-RequestId,x-amzn-ErrorType,x-amzn-ErrorMessage,Date' );
	res.setHeader( 'access-control-allow-methods', req.headers['access-control-allow-methods'] || 'GET, PUT, POST, DELETE, HEAD, OPTIONS' );
	res.setHeader( 'access-control-max-age', '172800' );
	res.setHeader( 'date', new Date().toUTCString() );
	res.setHeader( 'x-amzn-requestid', uuid() );
	Object.entries( headers, ( [ key, value ] ) => {
		res.setHeader( key, value );
	} );
}

module.exports = router()(
	get( '/', ( req, res ) => send( res, 200, { message: 'Service is running' } ) ),
	options( '/', ( req, res ) => {
		setHeaders( req, res );
		send( res, 200 );
	} ),
	post( '/', async ( req, res ) => {
		const body = await json( req );

		setHeaders( req, res, {
			'content-type': 'application/x-amz-json-1.1',
		});

		// Get existing ID.
		if ( req.headers['x-amz-target'] === 'AWSCognitoIdentityService.GetCredentialsForIdentity' ) {
			const expiration = new Date();
			expiration.setTime(Date.now() + (60 * 60 * 1000));
			send( res, 200, {
				'Credentials': {
					'AccessKeyId': 'not-needed',
					'Expiration': expiration.toISOString(),
					'SecretKey': 'not-needed',
					'SessionToken': 'not-needed',
				},
				'IdentityId': body.IdentityId,
			} );
			return;
		}

		// Get new ID.
		if ( req.headers['x-amz-target'] === 'AWSCognitoIdentityService.GetId' ) {
			send( res, 200, {
				'IdentityId': `us-east-1:${uuid()}`,
			} );
			return;
		}

		send( res, 500 );
	} )
);
