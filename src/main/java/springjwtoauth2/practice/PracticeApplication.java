package springjwtoauth2.practice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class PracticeApplication {

	public static void main(String[] args) {
		SpringApplication.run(PracticeApplication.class, args);
	}

}

//	1. JWT(JSON Web Token)는 뭘까?
//		JWT => 인증에 필요한 정보들을 암호화시킨 JSON 토큰
//		JWT를 이용한 인증 => 유저를 인증하고 식별하기 위한 Token 기반의 인증
//		JWT는 JSON 데이터를 Base64 URL-safe Encode를 통해 인코딩하여 직렬화한 것(토큰 안에는 개인키를 통한 전자서명이 있음)
//			+Base64 URL-safe Enocde => Base64 Encode를 URL에서 오류없이 사용하기 위해 +와/를 각각 -와_로 표현한 것

//		토큰 기반 인증 => 토큰 자체에 사용자의 정보가 포함되어 있음 (Self-contained)
//			클라이언트의 상태를 알아야했던 Stateful했던 환경에서 JWT를 사용하게 되면
//			서버가 클라이언트의 상태를 저장하지 않아도 되기 때문에 Stateless한 설계가 가능함

//		JWT를 이용한 인증 순서
//			1. 사용자가 로그인 시 아이디, 패스워드를 담아 서버에 요청
//			2. 서버에서 서명된(Signed) JWT를 생성하여 클라이언트에 응답으로 반환
//			3. 클라이언트는 응답으로 반환된 JWT를 사용하여 요청시 마다 Http Header에 JWT를 담아 요청
//			4. 서버에서 요청된 Http Header의 JWT를 검증하여 토큰이 유효한지 검증 후 유효하다면 요청에 맞는 응답 반환

//	2. JWT의 구조 => 다음 세가지 요소로 구성
//		Header.Payload.Signature (aaaaaa.bbbbbb.cccccc)

//		[Header] => 타입 or 전자서명 시 어떤 알고리즘이 사용되었는지 저장
//			ex{ "typ": "JWT", "alg": "HS512" }

//		[Payload] => Claim이 담겨있음
//			Payload에서 key-value 값으로 이루어진 것들이 모두 Claim
//			인증 시에 토큰에서 실제로 사용될 정를 의미함
//			여러 Claim들을 JWT 생성 시에 개발자가 어떤 Claim을 넣을지 맘대로 정할 수 있음
//				JWT 표준 스펙의 7가지 Claim
//					1. iss(Issuer) : 토큰 발급자
//					2. sub(Subjec) : 토큰 제목 - 토큰에서 사용자에 대한 식별값이 된다.
//					3. aud(Audience) : 토큰 대상자
//					4. exp(Expiration Time) : 토큰 만료 시간
//					5. nbf(Not Before) : 토큰 활성 날짜 (이 날짜 이전의 토큰은 활성화 되지 않음을 보장)
//					6. iat(Issued At) : 토큰 발급 시간
//					7. jti(JWT Id) : JWT 식별자 (issuer가 여러 명일 때 구분하기 위한 값)

//			+주의) Payload에는 암호화가 되어 있지 않기 때문에, 민감한 정보를 담지 않아야함
//					단순 식별을 위한 정보만 담아야함

//		[Signature] => 암호화의 구조가 담겨있음 (가장 중요)

//		*JWT 구조를 통해 이해하는 JWT 인증과정
//			1. JWT를 클라이언트가 서버에 요청 시 Http Header에 담아 요청
//			2. 서버에서 Http Header의 JWT를 꺼내서 가져옴
//			3. 클라이언트가 요청한 JWT를 서버가 가지고 있는 개인키를 가지고 Signature를 복호화
//			4. 복호화한 Signature의 base64UrlEncode(header)/base64UrlEncode(payload)가
//			   각각 요청한 JWT의 header, payload와 일치하는지 검증
//			5. 일치한다면 인증을 허용하고, 일치하지 않는다면 인증이 실패.
//		해당 과정에서 header나 payload의 값을 변조한 상태로 서버에 요청을 보내면
//		서버 JWT 검증 단계에서 Signature를 복호화한 header와 payload 값과 다르기 때문에
//		서버에서 인증 실패 응답을 보냄

//	3. JWT - AccessToken/RefreshToken
//		보통 JWT => AccessToken
//		RefreshToken의 등장 배경
//			Token의 탈취 위험에서부터 시작됨 => AccessToken의 유효 기간을 짧게 설정하면 해결 가능
//			하지만 AccessToken의 유효기간을 짧게 설정하면 귀찮고 번거로움
//			탈취 문제 -> 사용자 이용성에 trade-off 생김
//		이러한 문제를 해결하는 것이 RefreshToken
//		RefreshToken은 인증이 아니라, AccessToken을 재발급 해주는 역의 토큰임 (중요주ㅠㅇ욪우죵중요)

//		-AccessToken (인증 처리 역할)
//			처음 로그인 요청 시 서버에서 실제 유저의 정보가 담긴 AccessToken을 발행
//			클라이언트는 이 AccessToken을 저장한 후, 요청마다 AccessToken을 보내서
//			해당 AccessToken을 서버에서 검증 후 유효하면 요청에 맞는 응답을 진행

//		-RefreshToken (AccessToken 재발급 역할)
//			처음 로그인 요청 시 서버에서 AccessToken 재발급 용도인 RefreshToken을 발행
//			이때, 클라이언트는 RefreshToken을 저장하지 않고 RefreshToken은 보통 서버 DB에 저장
//			RefreshToken이 유효하면, AccessToken의 재발급을 진행

//		==> 사용자의 눈에는 별도의 재로그인 과정없이 AccessToken이 만료되지 않은 것처럼 동작함

