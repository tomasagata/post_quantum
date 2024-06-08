class Step {
  final String title;
  final String description;
  final Map<String, Object> parameters;
  final Map<String, Object> results;

  const Step({
    String? title,
    String? description,
    Map<String, Object>? parameters,
    Map<String, Object>? results
  }) :
    title = title ?? "Untitled step",
    description = description ?? "No description.",
    parameters = parameters ?? const <String, Object>{},
    results = results ?? const <String, Object>{};

  @override
  String toString() {
    return "$title: $description";
  }
}

class StepObserver {
  final List<Step> _steps = [];
  List<Step> get steps => _steps.sublist(0);

  StepObserver();


  void addStep({
    String? title,
    String? description,
    Map<String, Object>? parameters,
    Map<String, Object>? results
  }) {
    _steps.add(
        Step(
            title: title,
            description: description,
            parameters: parameters,
            results: results
        )
    );
  }

  void prettyPrint() {
    for (int i=0; i<steps.length; i++) {
      print("Step ${i+1}: ${steps[i].title}");
      print(" | ${steps[i].description}");
      print(" | ");

      print(" | Parameters:");
      for (var param in steps[i].parameters.entries) {
        print(" |  - ${param.key}: ${param.value}");
      }
      print(" | ");

      print(" | Results:");
      for (var res in steps[i].results.entries) {
        print(" |  - ${res.key}: ${res.value}");
      }
      print("");
    }
  }
}