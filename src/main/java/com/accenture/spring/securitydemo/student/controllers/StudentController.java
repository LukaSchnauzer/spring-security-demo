package com.accenture.spring.securitydemo.student.controllers;

import com.accenture.spring.securitydemo.student.models.Student;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping(value = "api/v1/students")
public class StudentController {

    private static final List<Student> STUDENT_LIST = Arrays.asList(
            new Student(1,"Juan"),
            new Student(2,"Carlos"),
            new Student(3,"Maria")
    );

    @GetMapping(value = "/{studentId}")
    public Student getStudent(@PathVariable(name = "studentId") Integer studentId){
        return STUDENT_LIST.stream()
                .filter( student -> studentId.equals(student.getId()) )
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Student "+ studentId + "does not exists"));
    }
}