package com.spring.main.controller;

import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.spring.main.domain.Student;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {
	private static final List<Student> STUDENTS=Arrays.asList(
				new Student(1,"quan"),
				new Student(2,"quyen")
			);
	
	@GetMapping(path = "{studentID}")
	public Student getStudent(@PathVariable("studentID") Integer studentID) {
		return STUDENTS.stream()
				.filter(student->studentID.equals(student.getId()))
				.findFirst()
				.orElseThrow(()->new IllegalStateException(
							"Student "+studentID+"does not esist"
						));
	}
}
