package com.accenture.spring.securitydemo.student.controllers;

import com.accenture.spring.securitydemo.student.models.Student;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class ManagementController {

    private static final List<Student> STUDENT_LIST = Arrays.asList(
            new Student(1,"Juan"),
            new Student(2,"Carlos"),
            new Student(3,"Maria")
    );

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_ADMINTRAINEE')")
    public List<Student> getAllStudents(){
        return STUDENT_LIST;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student;write')")
    public void saveStudent(@RequestBody Student student){
        System.out.println("Saved: "+student);
    }

    @DeleteMapping(path = "/{studentId}")
    @PreAuthorize("hasAuthority('student;write')")
    public void deleteStudent(@PathVariable(name = "studentId") Integer studentId){
        System.out.println("Deleted: "+studentId);
    }

    @PutMapping(path = "/{studentId}")
    @PreAuthorize("hasAuthority('student;write')")
    public void updateStudent(@PathVariable(name = "studentId") Integer studentId,@RequestBody Student student){
        System.out.println("Student "+studentId+" updated to "+student);
    }

    @GetMapping(value = "/{studentId}")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_ADMINTRAINEE')")
    public Student getStudent(@PathVariable(name = "studentId") Integer studentId){
        return STUDENT_LIST.stream()
                .filter( student -> studentId.equals(student.getId()) )
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Student "+ studentId + "does not exists"));
    }
}
