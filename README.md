# jwks-client
A golang package that provides automatic fetching of JWKS

## Usage

```go
authority, err := jwks.NewJwksAuthority(context.Background(), "jwks-server-url")
if err != nil {
    log.Fatalln(err)
}

...

token, err := authority.Validate(ctx, tokenBytes)
if err != nil {
    // Handle error
}

// Access token
```
