package br.com.thamyrescavalcante.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.thamyrescavalcante.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component         //class para o spring gerencie
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
               var servletPath = request.getServletPath() ;

               if(servletPath.startsWith("/tasks/")) {
                //Pegar a autenticação (usuario e senha)
                var authorization = request.getHeader("Authorization");

                //tira  a palavra Basic e o trim = remove todo espaço em branco deixando somente o Base64
                var authEncoded = authorization.substring("Basic".length()).trim();         
            
                byte[] authDecode = Base64.getDecoder().decode(authEncoded);   
                
                var authString = new String(authDecode);
                //System.out.println("Authorization");
                //System.out.println(authString); 
                //resultado: thamyrescavalcante:12345

                String[] credentioals = authString.split(":");
                String username = credentioals[0];
                String password = credentioals[1];
                System.out.println("Authorization");
                System.out.println(username); 
                //resultado: [thamyrescavalcante] [12345]

                //Validar Usuario
                var user = this.userRepository.findByUsername(username);
                if(user == null)        {
                    response.sendError(401);
                } else {
                    //Validar senha
                    var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                    if(passwordVerify.verified) {
                        //segue viagem
                        request.setAttribute("idUser", user.getId());  //vai setar o atributo iduser com o getId
                        filterChain.doFilter(request, response);
                    } else {
                        response.sendError(401);
                    }            
                }

            } else {
                filterChain.doFilter(request, response);

            }
    }    
    
}
