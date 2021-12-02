package entities;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@SpringBootApplication //Indica el punto de partida de la aplicación
public class Application {
	public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

	@Configuration  		//Hace referencia a que se trata a la clase con la configuracion de la seguridad
	@EnableWebSecurity		//Hace que las solicitudes pasen por el filtro de seguridad
	class WebSecurityConfig extends WebSecurityConfigurerAdapter {

		@Override 		//Configuración basica de seguridad 
		protected void configure(HttpSecurity http) throws Exception {
			//Indicamos que todas las solicitudes deben pasar por un filtro
			http.csrf().disable()
					.addFilterAfter(new JWTAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class)
					.authorizeRequests().antMatchers(HttpMethod.POST, "/user").permitAll().anyRequest().authenticated();
		}
	}
}
