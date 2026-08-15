package PsykeP.AuthAPI.auth.repositories;

import PsykeP.AuthAPI.auth.entities.RolSistema;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RolSistemaRepository extends JpaRepository<RolSistema, Long> {
}
