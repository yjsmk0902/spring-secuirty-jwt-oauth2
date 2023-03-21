package springjwtoauth2.practice.web.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import springjwtoauth2.practice.domain.dto.MemberSignUpDto;
import springjwtoauth2.practice.web.service.MemberService;

@RestController
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    //해당 URI로 회원가입 요청 시 자체 회원가입
    @PostMapping("/sign-up")
    public String signUp(@RequestBody MemberSignUpDto memberSignUpDto) throws Exception {
        memberService.signUp(memberSignUpDto);
        return "Sign-Up Complete!!";
    }
}
